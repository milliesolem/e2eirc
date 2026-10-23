package e2eirc

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// pinStore is the persistent trust registry: a map from casefolded nick to
// the identity fingerprint the user approved for that nick. It is shared by
// all connections and stored encrypted under a key derived from the
// identity seed.
type pinStore struct {
	mu   sync.Mutex
	pins map[string]string
}

var pins = pinStore{pins: map[string]string{}}

// Registry file layout:
//
//	magic(8) "E2EIRCTR" || version(1) || nonce(24) || XChaCha20-Poly1305(lines)
//
// where lines is "<nick> <fingerprint>\n" per entry.
const (
	registryMagic    = "E2EIRCTR"
	registryHeaderSz = len(registryMagic) + 1
)

func (s *pinStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := dataFile(registryFile)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) < registryHeaderSz || string(data[:len(registryMagic)]) != registryMagic {
		return errors.New("not an e2eirc trust registry")
	}
	if data[len(registryMagic)] != protoVersion {
		return fmt.Errorf("unsupported registry version %d", data[len(registryMagic)])
	}
	pt, err := openFile(sharedIdentity.registryKey, data, registryHeaderSz)
	if err != nil {
		return errors.New("trust registry is corrupt or belongs to another identity")
	}
	for _, line := range strings.Split(string(pt), "\n") {
		nick, fp, ok := strings.Cut(line, " ")
		if ok && nick != "" && fp != "" {
			s.pins[nick] = fp
		}
	}
	return nil
}

// save writes the registry. Caller holds s.mu.
func (s *pinStore) save() error {
	path, err := dataFile(registryFile)
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, nick := range s.sortedNicks() {
		b.WriteString(nick + " " + s.pins[nick] + "\n")
	}
	header := append([]byte(registryMagic), protoVersion)
	data, err := sealFile(sharedIdentity.registryKey, header, []byte(b.String()))
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func (s *pinStore) sortedNicks() []string {
	nicks := make([]string, 0, len(s.pins))
	for n := range s.pins {
		nicks = append(nicks, n)
	}
	sort.Strings(nicks)
	return nicks
}

// get returns the pinned fingerprint for a nick.
func (s *pinStore) get(nick string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp, ok := s.pins[ircLower(nick)]
	return fp, ok
}

// nicksFor returns every nick a fingerprint is pinned under.
func (s *pinStore) nicksFor(fp string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, n := range s.sortedNicks() {
		if s.pins[n] == fp {
			out = append(out, n)
		}
	}
	return out
}

// set pins a fingerprint to a nick, replacing any previous pin.
func (s *pinStore) set(nick, fp string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[ircLower(nick)] = fp
	return s.save()
}

// remove deletes the pin for a nick and reports whether one existed.
func (s *pinStore) remove(nick string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ircLower(nick)
	if _, ok := s.pins[key]; !ok {
		return false, nil
	}
	delete(s.pins, key)
	return true, s.save()
}

// all returns a sorted snapshot of (nick, fingerprint) pairs.
func (s *pinStore) all() [][2]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][2]string, 0, len(s.pins))
	for _, n := range s.sortedNicks() {
		out = append(out, [2]string{n, s.pins[n]})
	}
	return out
}
