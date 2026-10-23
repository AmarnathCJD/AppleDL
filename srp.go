package applemusic

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
	"sync"
)

// RFC 5054's 2048-bit group, stored in decimal by libAMSKit at ELF 0x11f696.
const srpPrimeHex = "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73"

var srpN, _ = new(big.Int).SetString(srpPrimeHex, 16)
var srpG = big.NewInt(2)

// SRPChallenge holds decoded GrandSlam init response fields. ServerPublic is
// the original decoded B bytes; its encoding is included in the client proof.
type SRPChallenge struct {
	Salt         []byte
	Iterations   int
	Scheme       PasswordScheme
	ServerPublic []byte
}

// SRPSession implements the native password exchange, not device attestation
// or Apple account login. It must not be copied. Like math/big, its modular
// arithmetic is not constant-time; this research implementation is unaudited.
type SRPSession struct {
	mu       sync.Mutex
	username string
	private  *big.Int
	public   []byte
	key      []byte
	m2       []byte
	stage    uint8 // 0: new, 1: awaiting server proof, 2: consumed
}

// NewSRPSession generates a fresh 256-bit private exponent using crypto/rand.
// The proof username uses the app's classic-locale ASCII lowercasing. Bytes
// outside A-Z are preserved, including UTF-8 sequences.
func NewSRPSession(username string) (*SRPSession, error) {
	if username == "" {
		return nil, errors.New("SRP username is required")
	}
	secret := make([]byte, 32)
	for {
		if _, err := rand.Read(secret); err != nil {
			return nil, errors.New("generate SRP private exponent failed")
		}
		if new(big.Int).SetBytes(secret).Sign() != 0 {
			break
		}
	}
	defer clear(secret)
	return newSRPWithPrivate(username, secret), nil
}

func newSRPWithPrivate(username string, secret []byte) *SRPSession {
	a := new(big.Int).SetBytes(secret)
	return &SRPSession{username: lowerASCII(username), private: a, public: padSRP(new(big.Int).Exp(srpG, a, srpN))}
}

// ELF 0x704efc calls classic-locale ctype<char>::do_tolower for each byte.
func lowerASCII(value string) string {
	b := []byte(value)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// PublicKey returns the 256-byte A2k value, with independent backing storage.
func (s *SRPSession) PublicKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.public...)
}

// Respond consumes one challenge and returns the minimally encoded M1. A failed
// attempt also consumes the session. Start a fresh session to retry.
func (s *SRPSession) Respond(password string, challenge SRPChallenge) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stage != 0 || s.private == nil {
		return nil, errors.New("SRP session cannot accept a challenge")
	}
	s.stage = 2
	defer func() { clear(s.private.Bits()); s.private = nil }()
	if len(challenge.ServerPublic) == 0 || len(challenge.ServerPublic) > 256 {
		return nil, errors.New("invalid SRP server public key")
	}
	b := new(big.Int).SetBytes(challenge.ServerPublic)
	if new(big.Int).Mod(b, srpN).Sign() == 0 {
		return nil, errors.New("invalid SRP server public key")
	}
	u := new(big.Int).SetBytes(hashSRP(s.public, padSRP(b)))
	if u.Sign() == 0 {
		return nil, errors.New("invalid SRP scrambling parameter")
	}
	passwordKey, err := DerivePassword(password, challenge.Salt, challenge.Iterations, challenge.Scheme)
	if err != nil {
		return nil, err
	}
	defer clear(passwordKey)
	x := new(big.Int).SetBytes(hashSRP(challenge.Salt, hashSRP([]byte(":"), passwordKey)))
	k := new(big.Int).SetBytes(hashSRP(padSRP(srpN), padSRP(srpG)))
	gx := new(big.Int).Exp(srpG, x, srpN)
	base := new(big.Int).Mod(new(big.Int).Sub(b, new(big.Int).Mul(k, gx)), srpN)
	exponent := new(big.Int).Add(s.private, new(big.Int).Mul(u, x))
	shared := new(big.Int).Exp(base, exponent, srpN)
	if shared.Sign() == 0 {
		return nil, errors.New("invalid SRP shared secret")
	}
	// The native implementation passes hashes through big integers, dropping
	// leading zero octets from K, M1 and the XOR term. See ELF 0x64bc4c.
	s.key = minimalSRP(hashSRP(padSRP(shared)))
	nHash, gHash := hashSRP(padSRP(srpN)), hashSRP(padSRP(srpG))
	for i := range nHash {
		nHash[i] ^= gHash[i]
	}
	m1 := minimalSRP(hashSRP(minimalSRP(nHash), hashSRP([]byte(s.username)), challenge.Salt, s.public, challenge.ServerPublic, s.key))
	s.m2 = hashSRP(s.public, m1, s.key)
	s.stage = 1
	return m1, nil
}

// VerifyServerProof consumes the server's M2 and releases K only on a match.
// Both minimal and zero-padded encodings (up to 32 bytes) are accepted.
// A verified proof establishes the SRP exchange, not a subscribed music session.
func (s *SRPSession) VerifyServerProof(proof []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stage != 1 {
		return nil, errors.New("SRP session is not awaiting a server proof")
	}
	s.stage = 2
	defer func() { clear(s.key); clear(s.m2); s.key, s.m2 = nil, nil }()
	if len(proof) == 0 || len(proof) > sha256.Size {
		return nil, errors.New("invalid SRP server proof")
	}
	var normalized [sha256.Size]byte
	copy(normalized[sha256.Size-len(proof):], proof)
	if subtle.ConstantTimeCompare(normalized[:], s.m2) != 1 {
		return nil, errors.New("invalid SRP server proof")
	}
	return append([]byte(nil), s.key...), nil
}

// Destroy consumes the session and clears the private exponent and pending key
// buffers. Call it when abandoning a manual exchange. It is safe to call again.
// Go strings, intermediate big integers and runtime copies are not guaranteed
// to be erased by this best-effort cleanup.
func (s *SRPSession) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.private != nil {
		clear(s.private.Bits())
		s.private = nil
	}
	clear(s.key)
	clear(s.m2)
	s.key, s.m2 = nil, nil
	s.stage = 2
}

func padSRP(n *big.Int) []byte   { return n.FillBytes(make([]byte, 256)) }
func minimalSRP(b []byte) []byte { return new(big.Int).SetBytes(b).Bytes() }
func hashSRP(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
}
