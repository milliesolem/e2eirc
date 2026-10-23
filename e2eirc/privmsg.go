package e2eirc

import (
	"errors"
	"log"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ircMaxLine    = 512 // including CRLF
	chunkMoreFlag = 1   // plaintext header bit: another chunk follows
	ctcpAction    = "\x01ACTION "
)

// clientPrivmsg handles a PRIVMSG typed by the user.
func (c *connection) clientPrivmsg(m *ircMessage) {
	if len(m.params) < 2 {
		c.writeServer(m.String())
		return
	}
	text := m.params[1]
	for _, target := range strings.Split(m.params[0], ",") {
		if target == "" {
			continue
		}
		if ircLower(target) == trustUserLower {
			c.handleTrustCommand(text)
			continue
		}
		c.sendMessage(target, text)
	}
}

// sendMessage encrypts and sends one message to one target.
func (c *connection) sendMessage(target, text string) {
	// CTCP other than ACTION (VERSION, PING, DCC, ...) is protocol
	// signalling rather than chat, so it is passed through in clear.
	if text == "" || (strings.HasPrefix(text, "\x01") && !strings.HasPrefix(text, ctcpAction)) {
		c.writeServer("PRIVMSG " + target + " :" + text)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isChannel(target) {
		c.sendChunks(target, false, c.bcast, text)
		return
	}

	p := c.peerFor(target)
	if p.canSendPrivate() {
		c.sendChunks(target, true, p.pairs[0].send, text)
		return
	}

	// No keys for this user yet: hold the message and start a key exchange.
	now := time.Now()
	p.outbox = append(p.outbox, outboundDM{text: text, since: now})
	if !p.outboxNotified {
		p.outboxNotified = true
		c.notice("Holding your message to " + cleanNick(target) + " until a key exchange with them completes.")
	}
	c.ensureHandshake(p, now, false)
}

// sendChunks splits text so every IRC line fits, seals each chunk and
// sends it. Caller holds c.mu.
func (c *connection) sendChunks(target string, private bool, key *sendKey, text string) {
	aad := msgAAD(private, c.fold(target))
	chunks := splitChunks(text, c.chunkBudget(target))
	for i, chunk := range chunks {
		flags := byte(0)
		if i < len(chunks)-1 {
			flags = chunkMoreFlag
		}
		pt := append([]byte{flags}, chunk...)
		wire, err := key.seal(aad, pt)
		if err != nil {
			log.Printf("encrypt for %s: %v", target, err)
			c.notice("Message to " + cleanNick(target) + " NOT sent: " + err.Error())
			return
		}
		c.writeServer("PRIVMSG " + target + " :" + msgPrefix + b64enc(wire))
	}
}

// chunkBudget is how many plaintext bytes fit in one line to target once
// the server has prepended our full ":nick!user@host " prefix for the
// recipients. The user and host parts are not known to us, so the maximum
// lengths common servers allow are assumed.
func (c *connection) chunkBudget(target string) int {
	nickLen := len(c.name)
	if nickLen == 0 {
		nickLen = 30
	}
	prefix := 1 + nickLen + 1 + 10 + 1 + 63 + 1
	overhead := len("PRIVMSG ") + len(target) + len(" :") + len(msgPrefix)
	b64 := ircMaxLine - 2 - prefix - overhead
	raw := b64 / 4 * 3
	pt := raw - counterSize - 16 - 1
	if pt < 32 {
		pt = 32
	}
	return pt
}

// splitChunks splits on UTF-8 boundaries into pieces of at most max bytes.
func splitChunks(text string, max int) []string {
	var chunks []string
	for len(text) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		if cut == 0 {
			cut = max
		}
		chunks = append(chunks, text[:cut])
		text = text[cut:]
	}
	return append(chunks, text)
}

// serverPrivmsg handles a PRIVMSG arriving from the IRC server.
func (c *connection) serverPrivmsg(m *ircMessage) {
	if len(m.params) < 2 || m.prefix == "" {
		c.writeClient(m.String())
		return
	}
	sender, text := m.nick(), m.text()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.fold(sender) == c.nameLower {
		c.deliverEcho(m)
		return
	}

	p := c.peerFor(sender)
	p.nick = sender

	switch {
	case strings.HasPrefix(text, ctrlPrefix):
		c.handleControl(p, text)
	case strings.HasPrefix(text, msgPrefix):
		if c.deliverEncrypted(p, m) {
			return
		}
		if c.trust.isDeclinedNick(c.fold(sender)) {
			if !p.declinedNotified {
				p.declinedNotified = true
				c.notice("Dropping encrypted messages from " + cleanNick(sender) + ": you declined their key. Reply TRUST " + cleanNick(sender) + " to reconsider.")
			}
			return
		}
		if len(p.inbox) >= maxInbox {
			p.inbox = p.inbox[1:]
			p.inboxDropped++
		}
		p.inbox = append(p.inbox, m)
		c.ensureHandshake(p, time.Now(), false)
	default:
		m.setText(markCleartext(text))
		c.writeClient(m.String())
	}
}

// deliverEncrypted decrypts an E2E1 line and delivers it. It returns false
// only when we lack a working key for it; garbage and replays are consumed.
// Caller holds c.mu.
func (c *connection) deliverEncrypted(p *peer, m *ircMessage) bool {
	wire, err := b64dec(strings.TrimPrefix(m.text(), msgPrefix))
	if err != nil {
		log.Printf("undecodable E2E1 line from %s", p.nick)
		return true
	}
	target := m.params[0]
	private := !c.isChannel(target)

	var aad, pt []byte
	var ctr uint64
	if private {
		if len(p.pairs) == 0 {
			return false
		}
		aad = msgAAD(true, c.nameLower)
		err = errBadCiphertext
		for _, pk := range p.pairs {
			pt, ctr, err = pk.recv.open(aad, wire)
			if err == nil || errors.Is(err, errReplay) {
				break
			}
		}
	} else {
		if p.bcast == nil {
			return false
		}
		aad = msgAAD(false, c.fold(target))
		pt, ctr, err = p.bcast.open(aad, wire)
	}
	if errors.Is(err, errReplay) {
		log.Printf("dropped replayed or reordered message from %s (counter %d)", p.nick, ctr)
		return true
	}
	if err != nil {
		return false
	}
	c.deliverPlaintext(p, m, string(aad), pt, ctr)
	return true
}

// deliverPlaintext reassembles chunks and writes the message to the client.
func (c *connection) deliverPlaintext(p *peer, m *ircMessage, aad string, pt []byte, ctr uint64) {
	if len(pt) == 0 {
		return
	}
	more := pt[0]&chunkMoreFlag != 0
	body := pt[1:]

	part := p.partials[aad]
	if part != nil && part.next != ctr {
		delete(p.partials, aad)
		c.notice("Incomplete message from " + cleanNick(p.nick) + " discarded (parts missing or reordered).")
		part = nil
	}
	if more {
		if part == nil {
			part = &partialMsg{since: time.Now()}
			p.partials[aad] = part
		}
		part.buf = append(part.buf, body...)
		part.next = ctr + 1
		part.parts++
		if len(part.buf) > maxPartialSize {
			delete(p.partials, aad)
			c.notice("Oversized message from " + cleanNick(p.nick) + " discarded.")
		}
		return
	}
	if part != nil {
		body = append(part.buf, body...)
		delete(p.partials, aad)
	}
	m.setText(string(body))
	c.writeClient(m.String())
}

// deliverEcho handles our own messages echoed back by the server
// (IRCv3 echo-message). Caller holds c.mu.
func (c *connection) deliverEcho(m *ircMessage) {
	text := m.text()
	if !strings.HasPrefix(text, msgPrefix) {
		if !strings.HasPrefix(text, ctrlPrefix) {
			c.writeClient(m.String())
		}
		return
	}
	wire, err := b64dec(strings.TrimPrefix(text, msgPrefix))
	if err != nil {
		return
	}
	target := m.params[0]
	var keys [][]byte
	if c.isChannel(target) {
		keys = [][]byte{c.bcast.key}
	} else if p, ok := c.peers[c.fold(target)]; ok {
		for _, pk := range p.pairs {
			keys = append(keys, pk.send.key)
		}
	}
	aad := msgAAD(!c.isChannel(target), c.fold(target))
	for _, key := range keys {
		if pt, _, err := openCounter(key, aad, wire); err == nil && len(pt) > 0 {
			m.setText(string(pt[1:]))
			c.writeClient(m.String())
			return
		}
	}
}

// markCleartext labels unencrypted text so it can never pass for an
// authenticated message. The marker is a prefix followed by a formatting
// reset, so colour codes in the text cannot hide it. CTCP ACTION keeps its
// frame so "/me" still renders; other CTCP is protocol signalling and is
// left alone.
func markCleartext(text string) string {
	const marker = "[CLEARTEXT] \x0f"
	if strings.HasPrefix(text, "\x01") {
		if strings.HasPrefix(text, ctcpAction) {
			inner := strings.TrimSuffix(text[len(ctcpAction):], "\x01")
			return ctcpAction + marker + inner + "\x01"
		}
		return text
	}
	return marker + text
}
