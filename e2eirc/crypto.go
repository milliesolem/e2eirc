package e2eirc

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Protocol constants. Every label is a distinct domain-separation string so
// a signature or key derived for one purpose can never be confused with
// another.
const (
	keySize = 32

	protoVersion byte = 1

	labelHello      = "e2eirc/1/hello"
	labelKeyex      = "e2eirc/1/keyex"
	labelTranscript = "e2eirc/1"
	labelKeys       = "e2eirc/1/keys"
	labelMsg        = "e2eirc/1/msg"
	labelRegistry   = "e2eirc/1/registry"

	// Prefixes used inside the text of an IRC PRIVMSG.
	msgPrefix  = "E2E1 "
	ctrlPrefix = "CTRL "
)

var (
	errReplay        = errors.New("replayed or out-of-order message")
	errBadCiphertext = errors.New("ciphertext malformed or authentication failed")
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return b
}

// zero overwrites key material. Best effort: Go gives no guarantee about
// copies the runtime or GC may have made.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func b64enc(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func b64dec(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// fingerprint is the lowercase hex SHA-256 of a raw Ed25519 public key.
func fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// groupFingerprint renders a fingerprint in blocks of four for humans.
func groupFingerprint(fp string) string {
	var b strings.Builder
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + 4
		if end > len(fp) {
			end = len(fp)
		}
		b.WriteString(fp[i:end])
	}
	return b.String()
}

//
// Message keys: ChaCha20-Poly1305 with an implicit 64-bit counter nonce.
//

// sendKey is an AEAD key that only this process ever encrypts with, plus the
// counter that makes every nonce unique. The counter is transmitted in clear
// in front of the ciphertext so the receiver can rebuild the nonce and
// reject replays.
type sendKey struct {
	key []byte
	ctr uint64
}

// recvKey is the receiving side of a sendKey: the key plus the highest
// counter accepted so far.
type recvKey struct {
	key  []byte
	last uint64
}

func newSendKey() *sendKey { return &sendKey{key: randomBytes(keySize)} }

func (k *sendKey) wipe() {
	if k != nil {
		zero(k.key)
	}
}

func (k *recvKey) wipe() {
	if k != nil {
		zero(k.key)
	}
}

const counterSize = 8

func counterNonce(ctr uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	return nonce
}

// seal encrypts plaintext under the next counter and returns
// counter(8) || ciphertext || tag(16).
func (k *sendKey) seal(aad, plaintext []byte) ([]byte, error) {
	if k.ctr == math.MaxUint64 {
		return nil, errors.New("message counter exhausted")
	}
	aead, err := chacha20poly1305.New(k.key)
	if err != nil {
		return nil, err
	}
	k.ctr++
	out := make([]byte, counterSize, counterSize+len(plaintext)+aead.Overhead())
	binary.BigEndian.PutUint64(out, k.ctr)
	return aead.Seal(out, counterNonce(k.ctr), plaintext, aad), nil
}

// open authenticates and decrypts a sealed message. Authentication is
// checked before the counter so only genuine messages are ever classified
// as replays; on success the counter is advanced.
func (k *recvKey) open(aad, wire []byte) (plaintext []byte, ctr uint64, err error) {
	pt, ctr, err := openCounter(k.key, aad, wire)
	if err != nil {
		return nil, ctr, err
	}
	if ctr <= k.last {
		return nil, ctr, errReplay
	}
	k.last = ctr
	return pt, ctr, nil
}

// openCounter is open without the replay check.
func openCounter(key, aad, wire []byte) (plaintext []byte, ctr uint64, err error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, 0, err
	}
	if len(wire) < counterSize+aead.Overhead() {
		return nil, 0, errBadCiphertext
	}
	ctr = binary.BigEndian.Uint64(wire[:counterSize])
	pt, err := aead.Open(nil, counterNonce(ctr), wire[counterSize:], aad)
	if err != nil {
		return nil, ctr, errBadCiphertext
	}
	return pt, ctr, nil
}

// msgAAD binds a chat ciphertext to its context: whether it was sent to a
// channel or as a private message, and the (casefolded) target. A message
// redirected by the server into a different channel or conversation fails
// authentication.
func msgAAD(private bool, target string) []byte {
	kind := "chan"
	if private {
		kind = "dm"
	}
	aad := make([]byte, 0, len(labelMsg)+len(kind)+len(target)+2)
	aad = append(aad, labelMsg...)
	aad = append(aad, 0)
	aad = append(aad, kind...)
	aad = append(aad, 0)
	aad = append(aad, target...)
	return aad
}

//
// Handshake: Ed25519-signed ephemeral X25519 with nick binding.
//

func lengthPrefixed(s string) []byte {
	if len(s) > 255 {
		s = s[:255]
	}
	return append([]byte{byte(len(s))}, s...)
}

// helloSigData is what the initiator signs: its identity and ephemeral key
// together with both nicks (casefolded) as it sees them, so a HELLO that the
// server forwards to a different recipient, or relabels as a different
// sender, fails verification.
func helloSigData(nickI, nickR string, idI, ephI []byte) []byte {
	d := []byte(labelHello)
	d = append(d, lengthPrefixed(nickI)...)
	d = append(d, lengthPrefixed(nickR)...)
	d = append(d, idI...)
	d = append(d, ephI...)
	return d
}

// transcript covers everything both parties contributed to a handshake.
func transcript(nickI, nickR string, idI, ephI, idR, ephR []byte) []byte {
	t := []byte(labelTranscript)
	t = append(t, lengthPrefixed(nickI)...)
	t = append(t, lengthPrefixed(nickR)...)
	t = append(t, idI...)
	t = append(t, ephI...)
	t = append(t, idR...)
	t = append(t, ephR...)
	return t
}

func keyexSigData(transcript, wrapped []byte) []byte {
	d := []byte(labelKeyex)
	d = append(d, transcript...)
	d = append(d, wrapped...)
	return d
}

// handshakeKeys are derived from the shared secret of one handshake.
type handshakeKeys struct {
	wrap  []byte // one-shot key wrapping the responder's broadcast key
	dmI2R []byte // private messages initiator -> responder
	dmR2I []byte // private messages responder -> initiator
}

func deriveHandshakeKeys(shared, transcript []byte) (*handshakeKeys, error) {
	salt := sha256.Sum256(transcript)
	okm, err := hkdf.Key(sha256.New, shared, salt[:], labelKeys, 3*keySize)
	if err != nil {
		return nil, err
	}
	return &handshakeKeys{wrap: okm[:keySize], dmI2R: okm[keySize : 2*keySize], dmR2I: okm[2*keySize:]}, nil
}

func (k *handshakeKeys) wipe() {
	zero(k.wrap)
	zero(k.dmI2R)
	zero(k.dmR2I)
}

// wrappedSize is the size of the sealed broadcast key: key || counter || tag.
const wrappedSize = keySize + counterSize + chacha20poly1305.Overhead

// wrapBroadcastKey seals the responder's broadcast key and current counter
// under the single-use wrap key. The nonce is all zero: the key is derived
// from fresh ephemerals and used exactly once.
func wrapBroadcastKey(wrapKey, transcript []byte, bk *sendKey) ([]byte, error) {
	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, keySize+counterSize)
	copy(pt, bk.key)
	binary.BigEndian.PutUint64(pt[keySize:], bk.ctr)
	defer zero(pt)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, pt, transcript), nil
}

func unwrapBroadcastKey(wrapKey, transcript, wrapped []byte) (key []byte, ctr uint64, err error) {
	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, 0, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	pt, err := aead.Open(nil, nonce, wrapped, transcript)
	if err != nil {
		return nil, 0, errBadCiphertext
	}
	if len(pt) != keySize+counterSize {
		return nil, 0, errBadCiphertext
	}
	return pt[:keySize], binary.BigEndian.Uint64(pt[keySize:]), nil
}

// Wire encoding of the two handshake messages. All fields are fixed width
// so the blobs are simply concatenated and base64 encoded.

const (
	helloSize = 1 + ed25519.PublicKeySize + keySize + ed25519.SignatureSize
	keyexSize = 1 + ed25519.PublicKeySize + keySize + wrappedSize + ed25519.SignatureSize
)

type helloMsg struct {
	id  ed25519.PublicKey
	eph []byte
	sig []byte
}

type keyexMsg struct {
	id      ed25519.PublicKey
	eph     []byte
	wrapped []byte
	sig     []byte
}

func encodeHello(h *helloMsg) string {
	b := make([]byte, 0, helloSize)
	b = append(b, protoVersion)
	b = append(b, h.id...)
	b = append(b, h.eph...)
	b = append(b, h.sig...)
	return b64enc(b)
}

func parseHello(s string) (*helloMsg, error) {
	b, err := b64dec(s)
	if err != nil {
		return nil, err
	}
	if len(b) != helloSize || b[0] != protoVersion {
		return nil, errors.New("malformed HELLO")
	}
	b = b[1:]
	return &helloMsg{
		id:  ed25519.PublicKey(b[:32]),
		eph: b[32:64],
		sig: b[64:],
	}, nil
}

func encodeKeyex(k *keyexMsg) string {
	b := make([]byte, 0, keyexSize)
	b = append(b, protoVersion)
	b = append(b, k.id...)
	b = append(b, k.eph...)
	b = append(b, k.wrapped...)
	b = append(b, k.sig...)
	return b64enc(b)
}

func parseKeyex(s string) (*keyexMsg, error) {
	b, err := b64dec(s)
	if err != nil {
		return nil, err
	}
	if len(b) != keyexSize || b[0] != protoVersion {
		return nil, errors.New("malformed KEYEX")
	}
	b = b[1:]
	return &keyexMsg{
		id:      ed25519.PublicKey(b[:32]),
		eph:     b[32:64],
		wrapped: b[64 : 64+wrappedSize],
		sig:     b[64+wrappedSize:],
	}, nil
}

func newEphemeral() *ecdh.PrivateKey {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic("X25519 key generation failed: " + err.Error())
	}
	return k
}

// sharedSecret performs X25519; crypto/ecdh rejects low-order inputs that
// would produce an all-zero result.
func sharedSecret(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

//
// At-rest encryption: XChaCha20-Poly1305 with a random 24-byte nonce.
//

func sealFile(key, header, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(chacha20poly1305.NonceSizeX)
	out := append([]byte{}, header...)
	out = append(out, nonce...)
	// The AAD is the whole header including the nonce.
	return aead.Seal(out, nonce, plaintext, out), nil
}

// openFile expects data = header || nonce || ciphertext, with header of the
// given length.
func openFile(key, data []byte, headerLen int) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	aadLen := headerLen + chacha20poly1305.NonceSizeX
	if len(data) < aadLen+aead.Overhead() {
		return nil, errBadCiphertext
	}
	nonce := data[headerLen:aadLen]
	pt, err := aead.Open(nil, nonce, data[aadLen:], data[:aadLen])
	if err != nil {
		return nil, errBadCiphertext
	}
	return pt, nil
}
