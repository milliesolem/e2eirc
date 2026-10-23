package e2eirc

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIRC is an in-memory IRC server that relays PRIVMSGs between the
// proxies under test. It is also the adversary: tests use it to replay,
// redirect and forge lines.
type fakeIRC struct {
	mu    sync.Mutex
	conns map[string]net.Conn // nick -> socket to that user's proxy
	seen  []string            // every PRIVMSG line relayed, for replay tests
	drop  func(from, line string) bool
}

func newFakeIRC() *fakeIRC { return &fakeIRC{conns: map[string]net.Conn{}} }

func (f *fakeIRC) serve(nick string, conn net.Conn) {
	f.mu.Lock()
	f.conns[nick] = conn
	f.mu.Unlock()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		m, ok := parseIRC(line)
		if !ok {
			continue
		}
		switch m.command {
		case "NICK":
			f.send(nick, ":srv 001 "+nick+" :Welcome")
			f.send(nick, ":srv 005 "+nick+" CASEMAPPING=rfc1459 CHANTYPES=# :are supported")
		case "PRIVMSG":
			if len(m.params) < 2 {
				continue
			}
			f.mu.Lock()
			drop := f.drop
			f.mu.Unlock()
			if drop != nil && drop(nick, line) {
				continue
			}
			f.relay(nick, m.params[0], m.params[1])
		}
	}
}

// relay delivers text from nick to target with a server-style prefix.
func (f *fakeIRC) relay(from, target, text string) {
	line := ":" + from + "!~u@host.example PRIVMSG " + target + " :" + text
	f.mu.Lock()
	f.seen = append(f.seen, line)
	f.mu.Unlock()
	if strings.HasPrefix(target, "#") {
		f.mu.Lock()
		var others []string
		for n := range f.conns {
			if n != from {
				others = append(others, n)
			}
		}
		f.mu.Unlock()
		for _, n := range others {
			f.send(n, line)
		}
		return
	}
	f.send(strings.ToLower(target), line)
}

func (f *fakeIRC) send(nick, line string) {
	f.mu.Lock()
	conn := f.conns[nick]
	f.mu.Unlock()
	if conn != nil {
		conn.Write([]byte(line + "\r\n"))
	}
}

func (f *fakeIRC) lastSeen(substr string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.seen) - 1; i >= 0; i-- {
		if strings.Contains(f.seen[i], substr) {
			return f.seen[i]
		}
	}
	return ""
}

// party is one user: their IRC client (us, the test) and their proxy.
type party struct {
	t     *testing.T
	nick  string
	proxy *connection
	in    net.Conn    // what the IRC client writes
	lines chan string // what the IRC client receives
}

func startParty(t *testing.T, irc *fakeIRC, nick string, id *identity) *party {
	clientProxy, clientUser := net.Pipe()
	serverProxy, serverFake := net.Pipe()
	c := newConnection(clientProxy, serverProxy)
	c.identity = id
	go c.run()
	go irc.serve(nick, serverFake)

	p := &party{t: t, nick: nick, proxy: c, in: clientUser, lines: make(chan string, 1000)}
	go func() {
		r := bufio.NewReader(clientUser)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				close(p.lines)
				return
			}
			p.lines <- strings.TrimRight(line, "\r\n")
		}
	}()
	t.Cleanup(func() { c.close() })
	p.send("NICK " + nick)
	p.expect("001")
	return p
}

func (p *party) send(line string) {
	p.t.Helper()
	if _, err := p.in.Write([]byte(line + "\r\n")); err != nil {
		p.t.Fatalf("%s: write: %v", p.nick, err)
	}
}

// expect waits for a line containing substr and returns it.
func (p *party) expect(substr string) string {
	p.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case line, ok := <-p.lines:
			if !ok {
				p.t.Fatalf("%s: connection closed while waiting for %q", p.nick, substr)
			}
			if strings.Contains(line, substr) {
				return line
			}
		case <-deadline:
			p.t.Fatalf("%s: timed out waiting for %q", p.nick, substr)
		}
	}
}

// expectNot asserts that no line containing substr arrives for a while.
func (p *party) expectNot(substr string) {
	p.t.Helper()
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case line := <-p.lines:
			if strings.Contains(line, substr) {
				p.t.Fatalf("%s: unexpected line %q", p.nick, line)
			}
		case <-deadline:
			return
		}
	}
}

var fpRe = regexp.MustCompile(`Fingerprint: ([0-9a-f ]+)$`)

// approve answers the pending trust prompt from nick, checking that the
// fingerprint shown matches the expected identity.
func (p *party) approve(nick string, expectedFP string) {
	p.t.Helper()
	line := p.expect("Fingerprint: ")
	fp := strings.ReplaceAll(fpRe.FindStringSubmatch(line)[1], " ", "")
	if fp != expectedFP {
		p.t.Fatalf("%s: prompt shows fingerprint %s, expected %s", p.nick, fp, expectedFP)
	}
	p.expect("To trust this key")
	p.send("PRIVMSG " + trustUser + " :TRUST " + nick + " " + fp[:12])
	p.expect("trusted with fingerprint")
}

func setupPair(t *testing.T) (*fakeIRC, *party, *party) {
	sharedConfig.dirPath = t.TempDir()
	idA, _ := newIdentityFromSeed(randomBytes(32))
	idB, _ := newIdentityFromSeed(randomBytes(32))
	sharedIdentity = idA
	pins = pinStore{pins: map[string]string{}}
	irc := newFakeIRC()
	alice := startParty(t, irc, "alice", idA)
	bob := startParty(t, irc, "bob", idB)
	return irc, alice, bob
}

func TestEndToEndChannelAndPrivate(t *testing.T) {
	irc, alice, bob := setupPair(t)

	// First contact: alice talks in a channel, bob cannot read it yet.
	alice.send("PRIVMSG #chan :hello bob")
	// Bob's proxy sends HELLO; alice is asked to trust bob.
	alice.approve("bob", bob.proxy.identity.fp)
	// Alice's KEYEX reaches bob; bob is asked to trust alice.
	bob.approve("alice", alice.proxy.identity.fp)
	line := bob.expect("hello bob")
	if !strings.HasPrefix(line, ":alice!") || strings.Contains(line, "CLEARTEXT") {
		t.Fatalf("delivered line %q", line)
	}
	if enc := irc.lastSeen("PRIVMSG #chan"); !strings.Contains(enc, msgPrefix) || strings.Contains(enc, "hello") {
		t.Fatalf("channel line on the wire was not encrypted: %q", enc)
	}

	// Private messages in both directions use the pairwise keys.
	bob.send("PRIVMSG alice :psst")
	if got := alice.expect("psst"); !strings.HasPrefix(got, ":bob!") {
		t.Fatalf("dm: %q", got)
	}
	alice.send("PRIVMSG Bob :reply")
	bob.expect("reply")
	if enc := irc.lastSeen("PRIVMSG Bob"); strings.Contains(enc, "reply") {
		t.Fatalf("dm on the wire was not encrypted: %q", enc)
	}

	// Bob's channel messages: alice holds no key for bob yet, so a second
	// handshake runs, now without prompts because both are pinned.
	bob.send("PRIVMSG #chan :bob here")
	alice.expect("bob here")

	// Replay of an authenticated line is dropped.
	replay := irc.lastSeen("PRIVMSG #chan")
	irc.send("alice", replay)
	alice.expectNot("bob here")

	// A private message redirected into the channel does not decrypt.
	dm := irc.lastSeen("PRIVMSG Bob")
	redirected := strings.Replace(dm, "PRIVMSG Bob", "PRIVMSG #chan", 1)
	irc.send("bob", redirected)
	bob.expectNot("reply")

	// A private message redirected to another recipient does not decrypt.
	redirected = strings.Replace(dm, "PRIVMSG Bob", "PRIVMSG alice", 1)
	irc.send("alice", redirected)
	alice.expectNot("reply")

	// Cleartext is marked, and cannot hide the marker behind formatting.
	irc.send("bob", ":alice!~u@h PRIVMSG #chan :plain \x0300,00text")
	if got := bob.expect("plain"); !strings.Contains(got, ":[CLEARTEXT] \x0fplain") {
		t.Fatalf("cleartext not marked: %q", got)
	}

	// The server cannot speak as the control user.
	irc.send("bob", ":"+trustUser+"!x@y PRIVMSG bob :Fingerprint: forged")
	irc.send("bob", ":"+strings.ToLower(trustUser)+"!x@y NOTICE bob :forged notice")
	bob.expectNot("forged")

	// Long messages are chunked and reassembled.
	long := strings.Repeat("0123456789", 60)
	alice.send("PRIVMSG #chan :" + long)
	if got := bob.expect(long); !strings.HasSuffix(got, ":"+long) {
		t.Fatalf("long message mangled: %q", got)
	}
	// Every wire line stayed within the IRC limit.
	irc.mu.Lock()
	for _, l := range irc.seen {
		if len(l)+2 > 512 {
			t.Errorf("line too long (%d bytes): %.60s...", len(l)+2, l)
		}
	}
	irc.mu.Unlock()

	// A dropped last chunk must not produce a truncated message.
	irc.mu.Lock()
	n := 0
	irc.drop = func(from, line string) bool {
		if from == "alice" && strings.Contains(line, "#chan") {
			n++
			return n == 3 // drop the third chunk
		}
		return false
	}
	irc.mu.Unlock()
	alice.send("PRIVMSG #chan :" + long)
	bob.expectNot(long[:100])
	irc.mu.Lock()
	irc.drop = nil
	irc.mu.Unlock()
	// The next complete message still gets through.
	alice.send("PRIVMSG #chan :after")
	bob.expect("Incomplete message from alice")
	bob.expect("after")
}

func TestRegenKeyAndUntrust(t *testing.T) {
	_, alice, bob := setupPair(t)
	alice.send("PRIVMSG #chan :one")
	alice.approve("bob", bob.proxy.identity.fp)
	bob.approve("alice", alice.proxy.identity.fp)
	bob.expect("one")

	alice.send("PRIVMSG " + trustUser + " :REGENKEY")
	alice.expect("regenerated")
	alice.send("PRIVMSG #chan :two")
	bob.expect("two") // re-keyed automatically, no prompts

	bob.send("PRIVMSG " + trustUser + " :UNTRUST alice")
	bob.expect("untrusted")
	alice.send("PRIVMSG #chan :three")
	// Bob's proxy asks alice for keys; alice auto-answers (bob is pinned);
	// bob is prompted again because the pin is gone.
	bob.approve("alice", alice.proxy.identity.fp)
	bob.expect("three")
}

func TestDeclineIsRememberedAndTrustReconsiders(t *testing.T) {
	_, alice, bob := setupPair(t)
	alice.send("PRIVMSG #chan :one")
	alice.expect("Fingerprint: ")
	alice.send("PRIVMSG " + trustUser + " :NO bob")
	alice.expect("NOT trusted")
	// A bare yes is never an approval.
	alice.send("PRIVMSG " + trustUser + " :yes")
	alice.expect("must name the key")

	alice.send("PRIVMSG #chan :two")
	alice.expectNot("Fingerprint: ")

	// Alice changes her mind.
	alice.send("PRIVMSG " + trustUser + " :TRUST bob")
	alice.expect("Requesting keys")
	bob.approve("alice", alice.proxy.identity.fp)
	alice.approve("bob", bob.proxy.identity.fp)
	alice.send("PRIVMSG #chan :three")
	bob.expect("three")
}

func TestWrongFingerprintIsRejected(t *testing.T) {
	_, alice, bob := setupPair(t)
	alice.send("PRIVMSG #chan :one")
	alice.expect("Fingerprint: ")
	alice.send("PRIVMSG " + trustUser + " :TRUST bob 0000000000")
	alice.expect("does not match")
	alice.expect("Fingerprint: ")
	alice.send("PRIVMSG " + trustUser + " :TRUST bob " + bob.proxy.identity.fp[:8])
	alice.expect("trusted with fingerprint")
}

func TestKeyChangeWarns(t *testing.T) {
	_, alice, bob := setupPair(t)
	pins.set("bob", fingerprint(randomBytes(32)))
	alice.send("PRIVMSG #chan :one")
	alice.expect("DIFFERENT identity key")
	alice.approve("bob", bob.proxy.identity.fp)
}

func TestHeldPrivateMessageSentAfterHandshake(t *testing.T) {
	_, alice, bob := setupPair(t)
	alice.send("PRIVMSG bob :are you there")
	alice.expect("Holding your message")
	bob.approve("alice", alice.proxy.identity.fp)
	alice.approve("bob", bob.proxy.identity.fp)
	alice.expect("held message(s) sent")
	bob.expect("are you there")
}

func TestRedirectedHandshakeFails(t *testing.T) {
	irc, alice, bob := setupPair(t)
	sharedIdentity = alice.proxy.identity
	idC, _ := newIdentityFromSeed(randomBytes(32))
	carol := startParty(t, irc, "carol", idC)

	// Bob and carol trust each other legitimately.
	carol.send("PRIVMSG bob :hi")
	bob.approve("carol", idC.fp)
	carol.approve("bob", bob.proxy.identity.fp)
	bob.expect("hi")

	// The server relabels traffic: bob's HELLO to "alice" is handed to
	// carol as if bob had addressed her. Carol (whom bob trusts) must not
	// answer it, because the signature binds the nick bob addressed.
	irc.mu.Lock()
	irc.drop = func(from, line string) bool {
		if from == "bob" && strings.HasPrefix(line, "PRIVMSG alice :CTRL HELLO") {
			irc.relay("bob", "carol", strings.TrimPrefix(line, "PRIVMSG alice :"))
			return true
		}
		return false
	}
	irc.mu.Unlock()
	irc.send("bob", fmt.Sprintf(":alice!~u@h PRIVMSG #chan :%sAAAA", msgPrefix))
	time.Sleep(300 * time.Millisecond)
	if kx := irc.lastSeen("PRIVMSG bob :CTRL KEYEX"); kx != "" {
		t.Fatalf("carol answered a redirected HELLO: %q", kx)
	}
	bob.proxy.mu.Lock()
	p := bob.proxy.peers["alice"]
	stranded := p != nil && (p.identity != nil || p.bcast != nil)
	bob.proxy.mu.Unlock()
	if stranded {
		t.Fatal("bob bound an identity to alice")
	}
}
