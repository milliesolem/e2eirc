package e2eirc

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"time"
)

const (
	maxInbox        = 32               // undecryptable lines held per peer
	maxPendingPeers = 64               // peers with an outstanding handshake
	maxPairKeys     = 2                // recent handshakes kept for DM decryption
	maxPartialSize  = 64 * 1024        // bytes buffered for one chunked message
	helloResend     = 30 * time.Second // minimum gap between HELLOs to one peer
	handshakeExpiry = 10 * time.Minute // outstanding HELLO is abandoned after this
	outboxExpiry    = 2 * time.Minute  // held private messages are dropped after this
	partialExpiry   = 15 * time.Second // incomplete chunked messages are dropped after this
)

// pairKeys are the directional private-message keys from one handshake.
type pairKeys struct {
	send *sendKey
	recv *recvKey
}

type outboundDM struct {
	text  string
	since time.Time
}

// partialMsg is a chunked message being reassembled.
type partialMsg struct {
	next  uint64 // counter the next chunk must carry
	buf   []byte
	parts int
	since time.Time
}

// peer is everything we know about another IRC user in this session.
type peer struct {
	conn *connection
	nick string // display form, as last seen from the server

	identity ed25519.PublicKey // learned through a verified, approved handshake
	bcast    *recvKey          // the peer's broadcast key (channel messages)
	pairs    []*pairKeys       // newest first

	// A handshake we initiated and are waiting on.
	eph       *ecdh.PrivateKey
	ephSince  time.Time
	helloSent time.Time

	inbox        []*ircMessage // lines we could not decrypt yet
	inboxDropped int

	outbox         []outboundDM // private messages waiting for keys
	outboxNotified bool

	partials map[string]*partialMsg // keyed by AAD

	declinedNotified bool
}

func newPeer(c *connection, nick string) *peer {
	return &peer{conn: c, nick: nick, partials: map[string]*partialMsg{}}
}

func (p *peer) fp() string {
	if p.identity == nil {
		return ""
	}
	return fingerprint(p.identity)
}

func (p *peer) canSendPrivate() bool { return len(p.pairs) > 0 }

// addPair installs keys from a completed handshake, keeping a couple of
// recent ones so simultaneous or replayed handshakes do not strand messages.
func (p *peer) addPair(send *sendKey, recv *recvKey) {
	p.pairs = append([]*pairKeys{{send: send, recv: recv}}, p.pairs...)
	for len(p.pairs) > maxPairKeys {
		old := p.pairs[len(p.pairs)-1]
		old.send.wipe()
		old.recv.wipe()
		p.pairs = p.pairs[:len(p.pairs)-1]
	}
}

func (p *peer) setBroadcastKey(key []byte, ctr uint64) {
	p.bcast.wipe()
	p.bcast = &recvKey{key: key, last: ctr}
}

// wipe discards all key material and pending state.
func (p *peer) wipe() {
	p.identity = nil
	p.bcast.wipe()
	p.bcast = nil
	for _, pk := range p.pairs {
		pk.send.wipe()
		pk.recv.wipe()
	}
	p.pairs = nil
	p.eph = nil
	p.inbox = nil
	p.inboxDropped = 0
	p.outbox = nil
	p.partials = map[string]*partialMsg{}
}
