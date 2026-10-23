package e2eirc

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"strings"
	"time"
)

// The handshake. I = initiator (cannot decrypt, or wants to send a private
// message), R = responder.
//
//	I -> R  CTRL HELLO  v1 || IdI || EI || Sign_I(label || nickI || nickR || IdI || EI)
//	R -> I  CTRL KEYEX  v1 || IdR || ER || wrapped || Sign_R(label || transcript || wrapped)
//
// transcript = label || nickI || nickR || IdI || EI || IdR || ER, with both
// nicks casefolded. ss = X25519(eI, ER); HKDF(ss, SHA256(transcript))
// yields the wrap key and two directional private-message keys. wrapped is
// R's broadcast key and counter sealed under the wrap key.

// pendingPeerCount counts peers with an outstanding HELLO. Caller holds c.mu.
func (c *connection) pendingPeerCount() int {
	n := 0
	for _, p := range c.peers {
		if p.eph != nil {
			n++
		}
	}
	return n
}

// ensureHandshake sends a HELLO to the peer unless one is already
// outstanding and recent; force skips that rate limit. Caller holds c.mu.
func (c *connection) ensureHandshake(p *peer, now time.Time, force bool) {
	if c.nameLower == "" {
		log.Printf("cannot start key exchange with %s before our nick is known", p.nick)
		return
	}
	if p.eph == nil {
		if c.pendingPeerCount() >= maxPendingPeers {
			log.Printf("too many outstanding key exchanges; not starting one with %s", p.nick)
			return
		}
		p.eph = newEphemeral()
		p.ephSince = now
	} else if !force && now.Sub(p.helloSent) < helloResend {
		return
	}
	p.helloSent = now

	h := &helloMsg{id: c.identity.pub, eph: p.eph.PublicKey().Bytes()}
	h.sig = c.identity.sign(helloSigData(c.nameLower, c.fold(p.nick), h.id, h.eph))
	c.sendControl(p, "HELLO", encodeHello(h))
}

func (c *connection) sendControl(p *peer, command, payload string) {
	c.writeServer("PRIVMSG " + p.nick + " :" + ctrlPrefix + command + " " + payload)
}

// handleControl dispatches a cleartext "CTRL ..." line from a peer.
// Caller holds c.mu.
func (c *connection) handleControl(p *peer, text string) {
	parts := strings.SplitN(text, " ", 3)
	if len(parts) != 3 {
		return
	}
	switch parts[1] {
	case "HELLO":
		c.handleHello(p, parts[2])
	case "KEYEX":
		c.handleKeyex(p, parts[2])
	default:
		log.Printf("unknown control command %q from %s", parts[1], p.nick)
	}
}

func (c *connection) handleHello(p *peer, blob string) {
	h, err := parseHello(blob)
	if err != nil {
		log.Printf("bad HELLO from %s: %v", p.nick, err)
		return
	}
	if h.id.Equal(c.identity.pub) || c.nameLower == "" {
		return
	}
	nickI, nickR := c.fold(p.nick), c.nameLower
	if !ed25519.Verify(h.id, helloSigData(nickI, nickR, h.id, h.eph), h.sig) {
		log.Printf("HELLO from %s failed signature verification (forged or redirected)", p.nick)
		return
	}
	fp := fingerprint(h.id)
	if c.trust.isDeclined(nickI, fp) {
		return
	}
	v := checkPin(p.nick, h.id)
	if v.kind == pinOK {
		c.replyKeyex(p, h)
		return
	}
	c.requestTrust(&trustRequest{peer: p, nick: p.nick, fp: fp, verdict: v, hello: h})
}

// replyKeyex answers a verified, approved HELLO with our broadcast key.
// Caller holds c.mu.
func (c *connection) replyKeyex(p *peer, h *helloMsg) {
	if c.nameLower == "" {
		return
	}
	nickI, nickR := c.fold(p.nick), c.nameLower
	eph := newEphemeral()
	ss, err := sharedSecret(eph, h.eph)
	if err != nil {
		log.Printf("HELLO from %s carries an invalid ephemeral key: %v", p.nick, err)
		return
	}
	defer zero(ss)
	tr := transcript(nickI, nickR, h.id, h.eph, c.identity.pub, eph.PublicKey().Bytes())
	keys, err := deriveHandshakeKeys(ss, tr)
	if err != nil {
		log.Printf("key derivation: %v", err)
		return
	}
	wrapped, err := wrapBroadcastKey(keys.wrap, tr, c.bcast)
	zero(keys.wrap)
	if err != nil {
		log.Printf("key wrap: %v", err)
		return
	}
	k := &keyexMsg{id: c.identity.pub, eph: eph.PublicKey().Bytes(), wrapped: wrapped}
	k.sig = c.identity.sign(keyexSigData(tr, wrapped))

	p.identity = h.id
	p.addPair(&sendKey{key: keys.dmR2I}, &recvKey{key: keys.dmI2R})
	c.sendControl(p, "KEYEX", encodeKeyex(k))
	c.flushOutbox(p)

	// If we are still waiting for this peer's keys ourselves, ask again now:
	// they are evidently online, and may just have approved us.
	if p.eph != nil {
		c.ensureHandshake(p, timeNow(), true)
	}
}

func (c *connection) handleKeyex(p *peer, blob string) {
	k, err := parseKeyex(blob)
	if err != nil {
		log.Printf("bad KEYEX from %s: %v", p.nick, err)
		return
	}
	if p.eph == nil {
		log.Printf("unexpected KEYEX from %s (no handshake outstanding)", p.nick)
		return
	}
	if k.id.Equal(c.identity.pub) || c.nameLower == "" {
		return
	}
	tr := c.initiatorTranscript(p, k)
	if !ed25519.Verify(k.id, keyexSigData(tr, k.wrapped), k.sig) {
		log.Printf("KEYEX from %s failed signature verification (forged, stale or redirected)", p.nick)
		return
	}
	fp := fingerprint(k.id)
	if c.trust.isDeclined(c.fold(p.nick), fp) {
		return
	}
	v := checkPin(p.nick, k.id)
	if v.kind == pinOK {
		c.finishKeyex(p, k)
		return
	}
	c.requestTrust(&trustRequest{peer: p, nick: p.nick, fp: fp, verdict: v, keyex: k})
}

func (c *connection) initiatorTranscript(p *peer, k *keyexMsg) []byte {
	return transcript(c.nameLower, c.fold(p.nick), c.identity.pub, p.eph.PublicKey().Bytes(), k.id, k.eph)
}

// finishKeyex installs the keys from a verified, approved KEYEX. Caller
// holds c.mu.
func (c *connection) finishKeyex(p *peer, k *keyexMsg) {
	if p.eph == nil {
		log.Printf("key exchange with %s expired before it was approved", p.nick)
		return
	}
	tr := c.initiatorTranscript(p, k)
	ss, err := sharedSecret(p.eph, k.eph)
	if err != nil {
		log.Printf("KEYEX from %s carries an invalid ephemeral key: %v", p.nick, err)
		return
	}
	defer zero(ss)
	keys, err := deriveHandshakeKeys(ss, tr)
	if err != nil {
		log.Printf("key derivation: %v", err)
		return
	}
	key, ctr, err := unwrapBroadcastKey(keys.wrap, tr, k.wrapped)
	zero(keys.wrap)
	if err != nil {
		log.Printf("KEYEX from %s: cannot unwrap broadcast key", p.nick)
		return
	}
	p.eph = nil
	p.identity = k.id
	p.addPair(&sendKey{key: keys.dmI2R}, &recvKey{key: keys.dmR2I})

	// Install the key with no history, so the messages that triggered this
	// exchange can be read, then move the replay floor up to the sender's
	// current counter so nothing older can be replayed to us later.
	p.setBroadcastKey(key, 0)
	c.retryInbox(p)
	if ctr > p.bcast.last {
		p.bcast.last = ctr
	}
	c.flushOutbox(p)
}

// retryInbox tries each held line exactly once with the new keys.
func (c *connection) retryInbox(p *peer) {
	inbox := p.inbox
	p.inbox = nil
	failed := 0
	for _, m := range inbox {
		if !c.deliverEncrypted(p, m) {
			failed++
		}
	}
	c.reportUndecryptable(p, failed, "sent under an old or unknown key")
}

func (c *connection) reportUndecryptable(p *peer, failed int, why string) {
	total := failed + p.inboxDropped
	p.inboxDropped = 0
	if total > 0 {
		c.notice(fmt.Sprintf("%d message(s) from %s could not be decrypted (%s).", total, cleanNick(p.nick), why))
	}
}

// flushOutbox sends private messages that were waiting for keys.
func (c *connection) flushOutbox(p *peer) {
	if !p.canSendPrivate() || len(p.outbox) == 0 {
		return
	}
	outbox := p.outbox
	p.outbox = nil
	p.outboxNotified = false
	for _, d := range outbox {
		c.sendChunks(p.nick, true, p.pairs[0].send, d.text)
	}
	c.notice(fmt.Sprintf("Key exchange with %s complete; %d held message(s) sent.", cleanNick(p.nick), len(outbox)))
}

// tick expires stale state. Called every few seconds; caller holds c.mu.
func (c *connection) tick(now time.Time) {
	for _, p := range c.peers {
		if p.eph != nil && now.Sub(p.ephSince) > handshakeExpiry {
			p.eph = nil
			failed := len(p.inbox)
			p.inbox = nil
			c.reportUndecryptable(p, failed, "no key exchange completed")
		}

		kept := p.outbox[:0]
		expired := 0
		for _, d := range p.outbox {
			if now.Sub(d.since) > outboxExpiry {
				expired++
			} else {
				kept = append(kept, d)
			}
		}
		p.outbox = kept
		if expired > 0 {
			c.notice(fmt.Sprintf("%d private message(s) to %s were NOT sent: no key exchange completed. They may not be running e2eirc.", expired, cleanNick(p.nick)))
		}
		if len(p.outbox) == 0 {
			p.outboxNotified = false
		}

		for aad, part := range p.partials {
			if now.Sub(part.since) > partialExpiry {
				delete(p.partials, aad)
				c.notice(fmt.Sprintf("Incomplete message from %s discarded (%d part(s) received, rest missing).", cleanNick(p.nick), part.parts))
			}
		}
	}
}
