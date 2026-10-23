package e2eirc

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	s := newSendKey()
	r := &recvKey{key: s.key}
	aad := msgAAD(false, "#chan")
	for i := 1; i <= 3; i++ {
		wire, err := s.seal(aad, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		pt, ctr, err := r.open(aad, wire)
		if err != nil || string(pt) != "hello" || ctr != uint64(i) {
			t.Fatalf("open: %v %q %d", err, pt, ctr)
		}
	}
}

func TestOpenRejectsReplayTamperingAndWrongContext(t *testing.T) {
	s := newSendKey()
	r := &recvKey{key: s.key}
	aad := msgAAD(true, "bob")
	wire, _ := s.seal(aad, []byte("secret"))
	if _, _, err := r.open(aad, wire); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.open(aad, wire); !errors.Is(err, errReplay) {
		t.Errorf("replay accepted: %v", err)
	}
	wire2, _ := s.seal(aad, []byte("second"))
	wire3, _ := s.seal(aad, []byte("third"))
	if _, _, err := r.open(aad, wire3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.open(aad, wire2); !errors.Is(err, errReplay) {
		t.Errorf("out-of-order message accepted: %v", err)
	}
	wire4, _ := s.seal(aad, []byte("fourth"))
	if _, _, err := r.open(msgAAD(false, "bob"), wire4); !errors.Is(err, errBadCiphertext) {
		t.Errorf("redirected message accepted: %v", err)
	}
	if _, _, err := r.open(msgAAD(true, "carol"), wire4); !errors.Is(err, errBadCiphertext) {
		t.Errorf("message for another recipient accepted: %v", err)
	}
	tampered := append([]byte{}, wire4...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := r.open(aad, tampered); !errors.Is(err, errBadCiphertext) {
		t.Errorf("tampered message accepted: %v", err)
	}
	if _, _, err := r.open(aad, wire4[:10]); !errors.Is(err, errBadCiphertext) {
		t.Errorf("truncated message accepted: %v", err)
	}
	if _, _, err := r.open(aad, wire4); err != nil {
		t.Errorf("genuine message rejected after failed attempts: %v", err)
	}
}

func TestWrapUnwrapBroadcastKey(t *testing.T) {
	bk := newSendKey()
	bk.ctr = 42
	wrapKey := randomBytes(keySize)
	tr := []byte("transcript")
	wrapped, err := wrapBroadcastKey(wrapKey, tr, bk)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != wrappedSize {
		t.Fatalf("wrapped size %d != %d", len(wrapped), wrappedSize)
	}
	key, ctr, err := unwrapBroadcastKey(wrapKey, tr, wrapped)
	if err != nil || !bytes.Equal(key, bk.key) || ctr != 42 {
		t.Fatalf("unwrap: %v", err)
	}
	if _, _, err := unwrapBroadcastKey(wrapKey, []byte("other"), wrapped); err == nil {
		t.Error("unwrap with wrong transcript succeeded")
	}
}

func TestHandshakeMessagesEncodeParse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	eph := newEphemeral()
	h := &helloMsg{id: pub, eph: eph.PublicKey().Bytes()}
	h.sig = ed25519.Sign(priv, helloSigData("alice", "bob", h.id, h.eph))
	enc := encodeHello(h)
	got, err := parseHello(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !got.id.Equal(pub) || !bytes.Equal(got.eph, h.eph) || !bytes.Equal(got.sig, h.sig) {
		t.Error("hello round trip mismatch")
	}
	if !ed25519.Verify(got.id, helloSigData("alice", "bob", got.id, got.eph), got.sig) {
		t.Error("signature does not verify")
	}
	if ed25519.Verify(got.id, helloSigData("alice", "carol", got.id, got.eph), got.sig) {
		t.Error("signature verifies for the wrong recipient nick")
	}
	for _, bad := range []string{"", "!!!", enc[:len(enc)-4], b64enc(append([]byte{2}, make([]byte, helloSize-1)...))} {
		if _, err := parseHello(bad); err == nil {
			t.Errorf("parseHello accepted %q", bad)
		}
	}

	k := &keyexMsg{id: pub, eph: h.eph, wrapped: make([]byte, wrappedSize), sig: make([]byte, ed25519.SignatureSize)}
	gk, err := parseKeyex(encodeKeyex(k))
	if err != nil || !gk.id.Equal(pub) || len(gk.wrapped) != wrappedSize || len(gk.sig) != ed25519.SignatureSize {
		t.Fatalf("keyex round trip: %v", err)
	}
	if _, err := parseKeyex(encodeHello(h)); err == nil {
		t.Error("parseKeyex accepted a HELLO")
	}
}

func TestDeriveHandshakeKeysDistinct(t *testing.T) {
	keys, err := deriveHandshakeKeys(randomBytes(32), []byte("t"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keys.wrap, keys.dmI2R) || bytes.Equal(keys.dmI2R, keys.dmR2I) || bytes.Equal(keys.wrap, keys.dmR2I) {
		t.Error("derived keys are not distinct")
	}
}

func TestSplitChunks(t *testing.T) {
	text := strings.Repeat("ab", 50) + "é" + strings.Repeat("c", 10)
	chunks := splitChunks(text, 7)
	if strings.Join(chunks, "") != text {
		t.Error("chunks do not reassemble")
	}
	for _, ch := range chunks {
		if len(ch) > 7 || !utf8Valid(ch) {
			t.Errorf("bad chunk %q", ch)
		}
	}
	if got := splitChunks("short", 100); len(got) != 1 || got[0] != "short" {
		t.Errorf("short text split: %q", got)
	}
	if got := splitChunks("", 100); len(got) != 1 || got[0] != "" {
		t.Errorf("empty text split: %q", got)
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

func TestMarkCleartext(t *testing.T) {
	if got := markCleartext("hi \x0300,00hidden"); !strings.HasPrefix(got, "[CLEARTEXT] \x0f") {
		t.Errorf("marker not a prefix: %q", got)
	}
	if got := markCleartext("\x01ACTION waves\x01"); got != "\x01ACTION [CLEARTEXT] \x0fwaves\x01" {
		t.Errorf("action: %q", got)
	}
	if got := markCleartext("\x01VERSION\x01"); got != "\x01VERSION\x01" {
		t.Errorf("ctcp request changed: %q", got)
	}
}

func TestSanitizeLineAndCleanNick(t *testing.T) {
	if got := sanitizeLine("a\r\nPRIVMSG #x :injected\x00"); strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("not sanitised: %q", got)
	}
	if got := cleanNick("bo\x03b\x7f"); got != "bob" {
		t.Errorf("cleanNick: %q", got)
	}
}

func TestGroupFingerprint(t *testing.T) {
	if got := groupFingerprint("0123456789ab"); got != "0123 4567 89ab" {
		t.Errorf("got %q", got)
	}
}

func TestIdentityFileRoundTrip(t *testing.T) {
	seed := randomBytes(ed25519.SeedSize)
	data, err := encryptIdentityFile(seed, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptIdentityFile(data, []byte("hunter2"))
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("decrypt: %v", err)
	}
	if _, err := decryptIdentityFile(data, []byte("hunter3")); !errors.Is(err, errBadCiphertext) {
		t.Errorf("wrong password: %v", err)
	}
	bad := append([]byte{}, data...)
	bad[len(identityMagic)+2] ^= 1 // argon2 time parameter
	if _, err := decryptIdentityFile(bad, []byte("hunter2")); err == nil {
		t.Error("tampered KDF parameters accepted")
	}
	huge := append([]byte{}, data...)
	huge[len(identityMagic)+5] = 0xff // memory parameter -> absurd
	if _, err := decryptIdentityFile(huge, []byte("hunter2")); err == nil || errors.Is(err, errBadCiphertext) {
		t.Errorf("absurd KDF parameters not rejected up front: %v", err)
	}
	if _, err := decryptIdentityFile([]byte("RSA PRIVATE KEY"), []byte("x")); err == nil {
		t.Error("non-identity file accepted")
	}
}

func TestPinStoreRoundTrip(t *testing.T) {
	sharedConfig.dirPath = t.TempDir()
	id, _ := newIdentityFromSeed(randomBytes(32))
	sharedIdentity = id
	pins = pinStore{pins: map[string]string{}}

	if err := pins.set("Alice", "aa"); err != nil {
		t.Fatal(err)
	}
	if err := pins.set("bob[x]", "bb"); err != nil {
		t.Fatal(err)
	}
	pins = pinStore{pins: map[string]string{}}
	if err := pins.load(); err != nil {
		t.Fatal(err)
	}
	if fp, ok := pins.get("alice"); !ok || fp != "aa" {
		t.Errorf("alice pin: %q %v", fp, ok)
	}
	if fp, ok := pins.get("BOB{X}"); !ok || fp != "bb" {
		t.Errorf("casefolded pin: %q %v", fp, ok)
	}
	if n := pins.nicksFor("aa"); len(n) != 1 || n[0] != "alice" {
		t.Errorf("nicksFor: %v", n)
	}
	if removed, _ := pins.remove("ALICE"); !removed {
		t.Error("remove failed")
	}
	if _, ok := pins.get("alice"); ok {
		t.Error("pin still present")
	}

	// A registry written under another identity must not load.
	other, _ := newIdentityFromSeed(randomBytes(32))
	sharedIdentity = other
	pins = pinStore{pins: map[string]string{}}
	if err := pins.load(); err == nil {
		t.Error("registry loaded under the wrong identity")
	}
}
