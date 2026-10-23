package e2eirc

import (
	"reflect"
	"testing"
)

func TestParseIRC(t *testing.T) {
	cases := []struct {
		in   string
		want *ircMessage
		ok   bool
	}{
		{"PRIVMSG #chan :hello world", &ircMessage{command: "PRIVMSG", params: []string{"#chan", "hello world"}, trailing: true}, true},
		{":nick!~user@host PRIVMSG bob :hi", &ircMessage{prefix: "nick!~user@host", command: "PRIVMSG", params: []string{"bob", "hi"}, trailing: true}, true},
		{"PING :irc.example.net", &ircMessage{command: "PING", params: []string{"irc.example.net"}, trailing: true}, true},
		{"PING irc.example.net", &ircMessage{command: "PING", params: []string{"irc.example.net"}}, true},
		{"nick alice", &ircMessage{command: "NICK", params: []string{"alice"}}, true},
		{"PRIVMSG #chan :", &ircMessage{command: "PRIVMSG", params: []string{"#chan", ""}, trailing: true}, true},
		{"PRIVMSG   #chan   :a  b", &ircMessage{command: "PRIVMSG", params: []string{"#chan", "a  b"}, trailing: true}, true},
		{"@time=2024;id=1 :srv 001 me :Welcome", &ircMessage{tags: "time=2024;id=1", prefix: "srv", command: "001", params: []string{"me", "Welcome"}, trailing: true}, true},
		{"ERROR", &ircMessage{command: "ERROR"}, true},
		{"", nil, false},
		{":onlyprefix", nil, false},
		{":prefix ", nil, false},
		{"@tagsonly", nil, false},
		{"PRIVMSG bob ::colon start", &ircMessage{command: "PRIVMSG", params: []string{"bob", ":colon start"}, trailing: true}, true},
	}
	for _, c := range cases {
		got, ok := parseIRC(c.in)
		if ok != c.ok {
			t.Errorf("parseIRC(%q) ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if ok && !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseIRC(%q)\n got %#v\nwant %#v", c.in, got, c.want)
		}
	}
}

func TestIRCRoundTrip(t *testing.T) {
	lines := []string{
		"PRIVMSG #chan :hello world",
		":nick!~user@host PRIVMSG bob :hi",
		"PING :irc.example.net",
		"PING irc.example.net",
		"@time=2024;id=1 :srv 001 me :Welcome",
		"MODE #chan +o bob",
		"PRIVMSG bob :",
		"PRIVMSG bob ::leading colon",
	}
	for _, l := range lines {
		m, ok := parseIRC(l)
		if !ok {
			t.Fatalf("parse failed for %q", l)
		}
		if got := m.String(); got != l {
			t.Errorf("round trip %q -> %q", l, got)
		}
	}
}

func TestIRCSetText(t *testing.T) {
	m, _ := parseIRC("PRIVMSG bob :x")
	m.setText("with spaces")
	if got := m.String(); got != "PRIVMSG bob :with spaces" {
		t.Errorf("got %q", got)
	}
	m.setText("nospace")
	if got := m.String(); got != "PRIVMSG bob :nospace" {
		t.Errorf("trailing must stay trailing, got %q", got)
	}
}

func TestIRCNick(t *testing.T) {
	m, _ := parseIRC(":alice!~a@h PRIVMSG bob :x")
	if m.nick() != "alice" {
		t.Errorf("nick %q", m.nick())
	}
	m.setNick("carol")
	if m.prefix != "carol!~a@h" {
		t.Errorf("prefix %q", m.prefix)
	}
	m2, _ := parseIRC(":server PING :x")
	if m2.nick() != "server" {
		t.Errorf("nick %q", m2.nick())
	}
	m2.setNick("s2")
	if m2.prefix != "s2" {
		t.Errorf("prefix %q", m2.prefix)
	}
}

func TestIRCLower(t *testing.T) {
	if ircLower("Bob[1]\\~") != "bob{1}|^" {
		t.Errorf("got %q", ircLower("Bob[1]\\~"))
	}
}
