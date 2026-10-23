package e2eirc

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// maxLineLength bounds a single IRC line read from either side. Servers cap
// lines at 512 bytes (8191 with IRCv3 tags); a generous limit protects us
// against an endless line.
const maxLineLength = 16384

const tickInterval = 5 * time.Second

func timeNow() time.Time { return time.Now() }

// connection is one IRC client session proxied to one IRC server session.
type connection struct {
	client net.Conn
	server net.Conn

	mu        sync.Mutex // guards everything below
	name      string     // our current nick, as the server knows it
	nameLower string

	asciiCase bool   // server advertised CASEMAPPING=ascii
	chantypes string // channel name prefixes from ISUPPORT

	identity *identity
	bcast    *sendKey         // every channel message is sealed with this
	peers    map[string]*peer // keyed by casefolded nick

	trust trustState

	clientWriteMu sync.Mutex
	serverWriteMu sync.Mutex
	closeOnce     sync.Once
	done          chan struct{}
}

func newConnection(client, server net.Conn) *connection {
	c := &connection{
		client:    client,
		server:    server,
		chantypes: "#&",
		identity:  sharedIdentity,
		bcast:     newSendKey(),
		peers:     map[string]*peer{},
		done:      make(chan struct{}),
	}
	c.trust.init()
	return c
}

func (c *connection) run() {
	log.Printf("session %s <-> %s", c.client.RemoteAddr(), c.server.RemoteAddr())
	go c.pump(c.client, c.handleClientLine)
	go c.ticker()
	c.pump(c.server, c.handleServerLine)
}

// pump reads IRC lines from conn until it fails, handing each to handle.
func (c *connection) pump(conn net.Conn, handle func(line string)) {
	r := bufio.NewReaderSize(conn, maxLineLength)
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			handle(strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("read: %v", err)
			}
			c.close()
			return
		}
	}
}

func (c *connection) ticker() {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case now := <-t.C:
			c.mu.Lock()
			c.tick(now)
			c.mu.Unlock()
		}
	}
}

func (c *connection) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		c.client.Close()
		c.server.Close()
		c.mu.Lock()
		c.bcast.wipe()
		for _, p := range c.peers {
			p.wipe()
		}
		c.mu.Unlock()
		log.Printf("session closed")
	})
}

// sanitizeLine makes sure a line we write cannot be split into several by
// the other side's parser.
func sanitizeLine(line string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, line)
}

func (c *connection) writeClient(line string) {
	c.clientWriteMu.Lock()
	defer c.clientWriteMu.Unlock()
	if _, err := io.WriteString(c.client, sanitizeLine(line)+"\r\n"); err != nil {
		log.Printf("write to client: %v", err)
	}
}

func (c *connection) writeServer(line string) {
	c.serverWriteMu.Lock()
	defer c.serverWriteMu.Unlock()
	if _, err := io.WriteString(c.server, sanitizeLine(line)+"\r\n"); err != nil {
		log.Printf("write to server: %v", err)
	}
}

// handleClientLine processes one line from the local IRC client.
func (c *connection) handleClientLine(line string) {
	m, ok := parseIRC(line)
	if !ok {
		c.writeServer(line)
		return
	}
	switch m.command {
	case "PRIVMSG":
		c.clientPrivmsg(m)
	case "NOTICE":
		// Never let anything addressed to the control pseudo-user reach
		// the network.
		if len(m.params) > 0 && ircLower(m.params[0]) == trustUserLower {
			return
		}
		c.writeServer(line)
	case "NICK":
		// Remember the nick we asked for; the server confirms it with NICK/001.
		if len(m.params) > 0 {
			c.setName(m.params[0])
		}
		c.writeServer(line)
	default:
		c.writeServer(line)
	}
}

// handleServerLine processes one line from the IRC server.
func (c *connection) handleServerLine(line string) {
	m, ok := parseIRC(line)
	if !ok {
		c.writeClient(line)
		return
	}
	// The control pseudo-user is ours alone: drop anything the server
	// attributes to it, whatever the command.
	if ircLower(m.nick()) == trustUserLower {
		log.Printf("dropped server line impersonating %s", trustUser)
		return
	}
	switch m.command {
	case "PRIVMSG":
		c.serverPrivmsg(m)
	case "001":
		// RPL_WELCOME: the first param is the nick the server actually gave us.
		if len(m.params) > 0 {
			c.setName(m.params[0])
		}
		c.writeClient(line)
	case "005":
		c.parseISupport(m.params)
		c.writeClient(line)
	case "NICK":
		// :old!u@h NICK :new -- either our own nick or a peer's changed.
		if len(m.params) > 0 {
			c.nickChanged(m.nick(), m.params[0])
		}
		c.writeClient(line)
	default:
		c.writeClient(line)
	}
}

// parseISupport picks the casemapping and channel prefixes out of
// RPL_ISUPPORT so nicks and channels are compared the way the server does.
func (c *connection) parseISupport(params []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range params {
		key, value, _ := strings.Cut(p, "=")
		switch key {
		case "CASEMAPPING":
			c.asciiCase = value == "ascii"
			c.nameLower = c.fold(c.name)
		case "CHANTYPES":
			if value != "" {
				c.chantypes = value
			}
		}
	}
}

// fold casefolds a nick or channel name the way the server does.
func (c *connection) fold(s string) string {
	if c.asciiCase {
		return strings.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}, s)
	}
	return ircLower(s)
}

func (c *connection) isChannel(target string) bool {
	return target != "" && strings.IndexByte(c.chantypes, target[0]) >= 0
}

func (c *connection) setName(nick string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.name = nick
	c.nameLower = c.fold(nick)
}

func (c *connection) nickChanged(from, to string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fold(from) == c.nameLower {
		c.name = to
		c.nameLower = c.fold(to)
		return
	}
	// A peer changed nick: carry their session state over to the new name.
	// Persistent trust pins are deliberately not moved; a later handshake
	// under the new nick asks the user to confirm it is the same person.
	fromKey, toKey := c.fold(from), c.fold(to)
	if p, ok := c.peers[fromKey]; ok {
		delete(c.peers, fromKey)
		if old, exists := c.peers[toKey]; exists {
			old.wipe()
		}
		p.nick = to
		c.peers[toKey] = p
	}
}

// peerFor returns the peer state for a nick, creating it if needed.
// Caller holds c.mu.
func (c *connection) peerFor(nick string) *peer {
	key := c.fold(nick)
	p, ok := c.peers[key]
	if !ok {
		p = newPeer(c, nick)
		c.peers[key] = p
	}
	return p
}
