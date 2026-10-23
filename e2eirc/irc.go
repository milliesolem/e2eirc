package e2eirc

import "strings"

// ircMessage is a parsed IRC protocol line (RFC 1459/2812 with IRCv3 tags
// tolerated and passed through untouched).
type ircMessage struct {
	tags     string // raw "@..." tag block, without the leading '@', or ""
	prefix   string // without the leading ':'
	command  string
	params   []string
	trailing bool // last param was sent as a ':'-prefixed trailing param
}

// parseIRC parses one IRC line (any trailing CR/LF already stripped).
// It never panics on malformed input; ok is false for lines with no command.
func parseIRC(line string) (m *ircMessage, ok bool) {
	m = &ircMessage{}
	rest := line

	if strings.HasPrefix(rest, "@") {
		tags, after, found := strings.Cut(rest[1:], " ")
		if !found {
			return nil, false
		}
		m.tags = tags
		rest = strings.TrimLeft(after, " ")
	}

	if strings.HasPrefix(rest, ":") {
		prefix, after, found := strings.Cut(rest[1:], " ")
		if !found {
			return nil, false
		}
		m.prefix = prefix
		rest = strings.TrimLeft(after, " ")
	}

	for rest != "" {
		if strings.HasPrefix(rest, ":") {
			m.params = append(m.params, rest[1:])
			m.trailing = true
			break
		}
		param, after, found := strings.Cut(rest, " ")
		if m.command == "" {
			m.command = strings.ToUpper(param)
		} else {
			m.params = append(m.params, param)
		}
		if !found {
			break
		}
		rest = strings.TrimLeft(after, " ")
	}

	if m.command == "" {
		return nil, false
	}
	return m, true
}

// String serialises the message back to an IRC line without CR/LF.
func (m *ircMessage) String() string {
	var b strings.Builder
	if m.tags != "" {
		b.WriteString("@")
		b.WriteString(m.tags)
		b.WriteString(" ")
	}
	if m.prefix != "" {
		b.WriteString(":")
		b.WriteString(m.prefix)
		b.WriteString(" ")
	}
	b.WriteString(m.command)
	for i, p := range m.params {
		b.WriteString(" ")
		last := i == len(m.params)-1
		if last && (m.trailing || p == "" || strings.HasPrefix(p, ":") || strings.Contains(p, " ")) {
			b.WriteString(":")
		}
		b.WriteString(p)
	}
	return b.String()
}

// nick returns the nick part of the prefix ("nick!user@host" -> "nick").
func (m *ircMessage) nick() string {
	nick, _, _ := strings.Cut(m.prefix, "!")
	return nick
}

// setNick replaces the nick part of the prefix, keeping user@host.
func (m *ircMessage) setNick(nick string) {
	_, rest, found := strings.Cut(m.prefix, "!")
	if found {
		m.prefix = nick + "!" + rest
	} else {
		m.prefix = nick
	}
}

// text returns the last parameter (the message body for PRIVMSG/NOTICE).
func (m *ircMessage) text() string {
	if len(m.params) == 0 {
		return ""
	}
	return m.params[len(m.params)-1]
}

// setText replaces the last parameter, always emitting it as trailing.
func (m *ircMessage) setText(text string) {
	if len(m.params) == 0 {
		m.params = []string{text}
	} else {
		m.params[len(m.params)-1] = text
	}
	m.trailing = true
}

// ircLower folds a nick or channel name using RFC 1459 casemapping, which
// is what the vast majority of IRC servers use: in addition to ASCII
// letters, the characters []\~ are the upper-case forms of {}|^.
func ircLower(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c == '[':
			c = '{'
		case c == ']':
			c = '}'
		case c == '\\':
			c = '|'
		case c == '~':
			c = '^'
		}
		b.WriteByte(c)
	}
	return b.String()
}
