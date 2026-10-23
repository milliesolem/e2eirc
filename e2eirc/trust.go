package e2eirc

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// The user talks to the proxy by messaging the pseudo-user $E2ECtrl. The
// proxy is the only writer to that window: every line from the server that
// claims to come from $E2ECtrl is dropped, and messages the user sends to
// it are never forwarded.
const trustUser = "$E2ECtrl"

var trustUserLower = ircLower(trustUser)

const maxTrustQueue = 16

type pinKind int

const (
	pinOK      pinKind = iota // (nick, fingerprint) is pinned
	pinNew                    // neither nick nor fingerprint known
	pinChanged                // nick is pinned to a different fingerprint
	pinAlias                  // fingerprint is pinned under other nicks
)

type pinVerdict struct {
	kind    pinKind
	oldFP   string
	aliases []string
}

// checkPin compares a peer's claimed identity with the trust registry.
func checkPin(nick string, id ed25519.PublicKey) pinVerdict {
	fp := fingerprint(id)
	if pinned, ok := pins.get(nick); ok {
		if pinned == fp {
			return pinVerdict{kind: pinOK}
		}
		return pinVerdict{kind: pinChanged, oldFP: pinned}
	}
	if aliases := pins.nicksFor(fp); len(aliases) > 0 {
		return pinVerdict{kind: pinAlias, aliases: aliases}
	}
	return pinVerdict{kind: pinNew}
}

// trustRequest is a handshake waiting for the user's decision. Exactly one
// of hello/keyex is set and says what to do once approved.
type trustRequest struct {
	peer    *peer
	nick    string
	fp      string
	verdict pinVerdict
	hello   *helloMsg
	keyex   *keyexMsg
}

type trustState struct {
	queue      []*trustRequest
	active     *trustRequest
	declined   map[string]bool // "nick\x00fp" declined this session
	suppressed int
}

func (t *trustState) init() { t.declined = map[string]bool{} }

func declineKey(nick, fp string) string { return ircLower(nick) + "\x00" + fp }

func (t *trustState) isDeclined(nick, fp string) bool { return t.declined[declineKey(nick, fp)] }

func (t *trustState) isDeclinedNick(nick string) bool {
	prefix := ircLower(nick) + "\x00"
	for k := range t.declined {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func (t *trustState) clearDeclined(nick string) {
	prefix := ircLower(nick) + "\x00"
	for k := range t.declined {
		if strings.HasPrefix(k, prefix) {
			delete(t.declined, k)
		}
	}
}

// requestTrust queues a prompt for the user. Caller holds c.mu.
func (c *connection) requestTrust(req *trustRequest) {
	t := &c.trust
	same := func(r *trustRequest) bool {
		return r != nil && ircLower(r.nick) == ircLower(req.nick) && r.fp == req.fp
	}
	// A repeated handshake for the same key just refreshes the pending
	// request; a HELLO and a KEYEX for the same key share one prompt.
	merge := func(r *trustRequest) {
		if req.hello != nil {
			r.hello = req.hello
		}
		if req.keyex != nil {
			r.keyex = req.keyex
		}
	}
	if same(t.active) {
		merge(t.active)
		return
	}
	for _, r := range t.queue {
		if same(r) {
			merge(r)
			return
		}
	}
	if len(t.queue) >= maxTrustQueue {
		t.suppressed++
		if t.suppressed == 1 {
			c.notice("Too many pending key requests; further ones are being dropped until you answer.")
		}
		return
	}
	t.queue = append(t.queue, req)
	if t.active == nil {
		c.nextTrustRequest()
	}
}

func (c *connection) nextTrustRequest() {
	t := &c.trust
	if len(t.queue) == 0 {
		t.active = nil
		t.suppressed = 0
		return
	}
	t.active = t.queue[0]
	t.queue = t.queue[1:]
	c.showTrustPrompt(t.active)
}

func (c *connection) showTrustPrompt(r *trustRequest) {
	nick := cleanNick(r.nick)
	switch r.verdict.kind {
	case pinChanged:
		c.notice("WARNING: " + nick + " is using a DIFFERENT identity key from the one you trusted before. Someone may be impersonating them.")
		c.notice("Previously trusted fingerprint: " + groupFingerprint(r.verdict.oldFP))
	case pinAlias:
		c.notice(nick + " is presenting the identity key you already trust as " + strings.Join(r.verdict.aliases, ", ") + ". Is this the same person?")
	default:
		c.notice(nick + " would like to exchange keys with you. Verify the fingerprint with them over another channel.")
	}
	c.notice("Fingerprint: " + groupFingerprint(r.fp))
	c.notice("To trust this key reply:  TRUST " + nick + " " + r.fp[:8] + "   (at least the first 8 characters of the fingerprint). To refuse:  NO " + nick)
	if len(c.trust.queue) > 0 {
		c.notice(fmt.Sprintf("(%d more request(s) waiting)", len(c.trust.queue)))
	}
}

// handleTrustCommand processes a line the user sent to $E2ECtrl.
func (c *connection) handleTrustCommand(text string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fields := strings.Fields(text)
	if len(fields) == 0 {
		return
	}
	arg := func(i int) string {
		if i < len(fields) {
			return fields[i]
		}
		return ""
	}

	switch strings.ToUpper(fields[0]) {
	case "TRUST":
		c.cmdTrust(arg(1), strings.ToLower(strings.Join(fields[2:], "")))
	case "NO", "N", "DENY", "REFUSE":
		c.cmdDecline(arg(1))
	case "YES", "Y":
		c.notice("For your safety an approval must name the key: reply  TRUST <nick> <fingerprint prefix>  as shown in the request.")
	case "UNTRUST":
		c.cmdUntrust(arg(1))
	case "LISTTRUST", "LIST":
		c.cmdListTrust()
	case "REGENKEY":
		c.regenerateBroadcastKey()
		c.notice("Broadcast key regenerated. Peers will re-request it automatically.")
	case "HELP":
		c.cmdHelp()
	default:
		c.notice("Command not recognised: '" + cleanNick(fields[0]) + "'. Type HELP for the list of commands.")
	}
}

func (c *connection) cmdTrust(nick, fpPrefix string) {
	if nick == "" {
		c.notice("Usage: TRUST <nick> <fingerprint prefix>")
		return
	}
	r := c.trust.active
	if r != nil && ircLower(r.nick) == ircLower(nick) {
		if len(fpPrefix) < 8 || !strings.HasPrefix(r.fp, fpPrefix) {
			c.notice("That fingerprint does not match the pending request for " + cleanNick(nick) + ". Nothing was trusted.")
			c.showTrustPrompt(r)
			return
		}
		c.approve(r)
		return
	}

	// No prompt pending for this nick: treat as "start / allow a key exchange".
	c.trust.clearDeclined(nick)
	for _, q := range c.trust.queue {
		if ircLower(q.nick) == ircLower(nick) {
			c.notice("A request from " + cleanNick(nick) + " is queued; answer the current one first.")
			return
		}
	}
	p := c.peerFor(nick)
	p.declinedNotified = false
	c.ensureHandshake(p, timeNow(), true)
	c.notice("Requesting keys from " + cleanNick(nick) + ". You will be asked to confirm their fingerprint.")
}

func (c *connection) approve(r *trustRequest) {
	if err := pins.set(r.nick, r.fp); err != nil {
		c.notice("Could not save the trust registry: " + err.Error())
	}
	c.notice(cleanNick(r.nick) + " trusted with fingerprint " + groupFingerprint(r.fp) + ".")
	if r.hello != nil {
		c.replyKeyex(r.peer, r.hello)
	}
	if r.keyex != nil {
		c.finishKeyex(r.peer, r.keyex)
	}
	c.nextTrustRequest()
}

func (c *connection) cmdDecline(nick string) {
	r := c.trust.active
	if r == nil {
		c.notice("No pending request.")
		return
	}
	if nick != "" && ircLower(nick) != ircLower(r.nick) {
		c.notice("The pending request is from " + cleanNick(r.nick) + ", not " + cleanNick(nick) + ".")
		return
	}
	c.trust.declined[declineKey(r.nick, r.fp)] = true
	p := r.peer
	p.eph = nil
	failed := len(p.inbox)
	p.inbox = nil
	c.reportUndecryptable(p, failed, "key declined")
	c.notice(cleanNick(r.nick) + " was NOT trusted. Their key will be ignored for this session; reply TRUST " + cleanNick(r.nick) + " to reconsider.")
	c.nextTrustRequest()
}

// cmdUntrust forgets a nick's pin and keys and rotates our broadcast key,
// since the peer already holds the current one.
func (c *connection) cmdUntrust(nick string) {
	if nick == "" {
		c.notice("Usage: UNTRUST <nick>")
		return
	}
	removed, err := pins.remove(nick)
	if err != nil {
		c.notice("Could not save the trust registry: " + err.Error())
	}
	var fp string
	for key, p := range c.peers {
		if key == c.fold(nick) {
			fp = p.fp()
			p.wipe()
			delete(c.peers, key)
		}
	}
	if fp != "" {
		for key, p := range c.peers {
			if p.fp() == fp {
				p.wipe()
				delete(c.peers, key)
			}
		}
	}
	if !removed && fp == "" {
		c.notice(cleanNick(nick) + " was not trusted.")
		return
	}
	c.regenerateBroadcastKey()
	c.notice(cleanNick(nick) + " untrusted. Your broadcast key has been regenerated; remaining trusted peers will re-request it automatically.")
	if fp != "" {
		if others := pins.nicksFor(fp); len(others) > 0 {
			c.notice("Note: the same identity key is still trusted as " + strings.Join(others, ", ") + ". Use UNTRUST on those nicks too if that is not intended.")
		}
	}
}

func (c *connection) cmdListTrust() {
	all := pins.all()
	if len(all) == 0 {
		c.notice("No trusted keys.")
	}
	for _, e := range all {
		c.notice(e[0] + "  " + groupFingerprint(e[1]))
	}
	c.notice("Your own fingerprint: " + groupFingerprint(c.identity.fp))
	for _, p := range c.peers {
		state := "no keys"
		switch {
		case p.bcast != nil && p.canSendPrivate():
			state = "keys exchanged"
		case p.canSendPrivate():
			state = "can send private messages; waiting for their channel key"
		case p.eph != nil:
			state = "key exchange in progress"
		}
		if p.identity != nil {
			state += ", identity " + p.fp()[:16]
		}
		c.notice("session: " + cleanNick(p.nick) + " - " + state)
	}
}

func (c *connection) cmdHelp() {
	for _, line := range []string{
		"TRUST <nick> <fingerprint prefix>  approve a pending key request (or start one if none is pending)",
		"NO [nick]                          refuse the pending key request",
		"UNTRUST <nick>                     forget a trusted key and rotate your broadcast key",
		"LISTTRUST                          show trusted keys and session state",
		"REGENKEY                           rotate your broadcast key",
		"HELP                               this text",
	} {
		c.notice(line)
	}
}

// regenerateBroadcastKey makes a fresh channel key. Caller holds c.mu.
func (c *connection) regenerateBroadcastKey() {
	c.bcast.wipe()
	c.bcast = newSendKey()
}

// notice writes a line to the user's client as the $E2ECtrl pseudo-user.
func (c *connection) notice(text string) {
	name := c.name
	if name == "" {
		name = "*"
	}
	c.writeClient(":" + trustUser + "!e2eirc@internal PRIVMSG " + name + " :" + text)
}

// cleanNick strips control characters from a server-supplied nick before it
// is embedded in text the proxy generates.
func cleanNick(nick string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, nick)
}
