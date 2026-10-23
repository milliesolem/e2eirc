package e2eirc

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// identity is the user's persistent Ed25519 signing key.
type identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	fp   string

	registryKey []byte // encrypts the trust registry at rest
}

var sharedIdentity *identity

// Identity file layout (all integers big endian):
//
//	magic(8) "E2EIRCID" || version(1) || argon2 time(4) || memory KiB(4) ||
//	threads(1) || salt(16) || nonce(24) || XChaCha20-Poly1305(seed(32))
//
// The AAD is every byte before the ciphertext, so the parameters and salt
// are authenticated by the password-derived key.
const (
	identityMagic    = "E2EIRCID"
	identityHeaderSz = len(identityMagic) + 1 + 4 + 4 + 1 + argonSaltSize

	argonSaltSize        = 16
	argonTime     uint32 = 3
	argonMemory   uint32 = 64 * 1024 // KiB
	argonThreads  uint8  = 1

	// Upper bounds accepted when reading a file, so a tampered header
	// cannot make us allocate absurd amounts of memory.
	argonMaxTime   uint32 = 64
	argonMaxMemory uint32 = 1024 * 1024
)

func newIdentityFromSeed(seed []byte) (*identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("bad seed length")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	regKey, err := hkdf.Key(sha256.New, seed, nil, labelRegistry, keySize)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &identity{priv: priv, pub: pub, fp: fingerprint(pub), registryKey: regKey}, nil
}

func (id *identity) sign(data []byte) []byte { return ed25519.Sign(id.priv, data) }

// Unlock loads the identity key (creating one on first run) and the trust
// registry. It exits the program if that is impossible.
func Unlock() {
	id, err := loadOrCreateIdentity()
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	sharedIdentity = id
	fmt.Println("Your fingerprint: " + groupFingerprint(id.fp))
	if err := pins.load(); err != nil {
		log.Fatalf("trust registry: %v", err)
	}
}

func loadOrCreateIdentity() (*identity, error) {
	path, err := dataFile(identityFile)
	if err != nil {
		return nil, err
	}
	warnLegacyFiles(filepath.Dir(path))

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return createIdentity(path)
	}
	if err != nil {
		return nil, err
	}

	fmt.Println("Identity key found.")
	for attempt := 0; attempt < 3; attempt++ {
		prompt := "Enter your identity key password"
		if attempt > 0 {
			prompt = "Password incorrect. Try again"
		}
		password, err := readPassword(prompt, attempt == 0)
		if err != nil {
			return nil, err
		}
		seed, err := decryptIdentityFile(data, password)
		zero(password)
		if err == nil {
			defer zero(seed)
			return newIdentityFromSeed(seed)
		}
		if !errors.Is(err, errBadCiphertext) {
			return nil, err
		}
	}
	return nil, errors.New("too many failed password attempts")
}

func createIdentity(path string) (*identity, error) {
	fmt.Println("No identity key found. Generating a new Ed25519 identity.")
	for {
		password, err := readPassword("Choose a password for your identity key. If you lose it you will not be able to prove your identity on chat", true)
		if err != nil {
			return nil, err
		}
		if len(password) == 0 {
			fmt.Println("The password must not be empty.")
			continue
		}
		if sharedConfig.keyPassword == "" {
			confirm, err := readPassword("Confirm password", false)
			if err != nil {
				return nil, err
			}
			same := bytes.Equal(password, confirm)
			zero(confirm)
			if !same {
				fmt.Println("Passwords do not match.")
				zero(password)
				continue
			}
		}
		seed := randomBytes(ed25519.SeedSize)
		defer zero(seed)
		data, err := encryptIdentityFile(seed, password)
		zero(password)
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(path, data); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Println("Identity key written to " + path)
		return newIdentityFromSeed(seed)
	}
}

func encryptIdentityFile(seed, password []byte) ([]byte, error) {
	header := make([]byte, 0, identityHeaderSz)
	header = append(header, identityMagic...)
	header = append(header, protoVersion)
	header = binary.BigEndian.AppendUint32(header, argonTime)
	header = binary.BigEndian.AppendUint32(header, argonMemory)
	header = append(header, argonThreads)
	header = append(header, randomBytes(argonSaltSize)...)

	key := argon2.IDKey(password, header[len(header)-argonSaltSize:], argonTime, argonMemory, argonThreads, keySize)
	defer zero(key)
	return sealFile(key, header, seed)
}

func decryptIdentityFile(data, password []byte) ([]byte, error) {
	if len(data) < identityHeaderSz || string(data[:len(identityMagic)]) != identityMagic {
		return nil, errors.New("not an e2eirc identity file")
	}
	h := data[len(identityMagic):]
	if h[0] != protoVersion {
		return nil, fmt.Errorf("unsupported identity file version %d", h[0])
	}
	t := binary.BigEndian.Uint32(h[1:5])
	m := binary.BigEndian.Uint32(h[5:9])
	p := h[9]
	salt := h[10 : 10+argonSaltSize]
	if t == 0 || t > argonMaxTime || m < 8 || m > argonMaxMemory || p == 0 {
		return nil, errors.New("identity file has unreasonable KDF parameters")
	}
	key := argon2.IDKey(password, salt, t, m, p, keySize)
	defer zero(key)
	return openFile(key, data, identityHeaderSz)
}

// readPassword prompts for a password. The -key flag is used, once, for
// the first attempt when allowFlag is set.
func readPassword(prompt string, allowFlag bool) ([]byte, error) {
	if allowFlag && sharedConfig.keyPassword != "" {
		return []byte(sharedConfig.keyPassword), nil
	}
	fmt.Print(prompt + ": ")
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Println()
		return pw, err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// warnLegacyFiles tells the user about files from the RSA-based 0.0.x
// versions, which are incompatible, and moves them out of the way.
func warnLegacyFiles(dir string) {
	legacy := filepath.Join(dir, "private_key.pem")
	if _, err := os.Stat(legacy); err == nil {
		fmt.Println("Found an RSA private key from an older e2eirc version. It is no longer used;")
		fmt.Println("a new Ed25519 identity will be created. The old file is kept as private_key.pem.old.")
		if err := os.Rename(legacy, legacy+".old"); err != nil {
			log.Printf("could not rename %s: %v", legacy, err)
		}
	}
	reg := filepath.Join(dir, registryFile)
	if data, err := os.ReadFile(reg); err == nil && bytes.HasPrefix(data, []byte("RSA ")) {
		fmt.Println("Found a trusted key list from an older e2eirc version. It is incompatible and")
		fmt.Println("has been moved to trusted_keys.old; you will be asked to trust peers again.")
		if err := os.Rename(reg, reg+".old"); err != nil {
			log.Printf("could not rename %s: %v", reg, err)
		}
	}
}
