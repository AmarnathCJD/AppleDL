package applemusic

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type srpFixture struct {
	Name, Username, Password, Scheme string
	Iterations                       int
	A, B, K, M1, M2                  string
	Private                          string `json:"a"`
	Salt                             string
}

func srpFixtures(t *testing.T) []srpFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/srp.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []srpFixture
	if err := json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func unhex(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSRPUsernameClassicLocale(t *testing.T) {
	if got := newSRPWithPrivate("\u00c4BC@EXAMPLE.invalid", []byte{1}).username; got != "\u00c4bc@example.invalid" {
		t.Fatal("username normalization changed non-ASCII bytes")
	}
}

func fixtureSession(t *testing.T, f srpFixture) (*SRPSession, SRPChallenge) {
	t.Helper()
	return newSRPWithPrivate(f.Username, unhex(t, f.Private)), SRPChallenge{
		Salt: unhex(t, f.Salt), ServerPublic: unhex(t, f.B),
		Iterations: f.Iterations, Scheme: PasswordScheme(f.Scheme),
	}
}

func TestSRPIndependentServerFixtures(t *testing.T) {
	for _, f := range srpFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			s, challenge := fixtureSession(t, f)
			if !bytes.Equal(s.PublicKey(), unhex(t, f.A)) {
				t.Fatal("public key mismatch")
			}
			m1, err := s.Respond(f.Password, challenge)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(m1, unhex(t, f.M1)) {
				t.Fatal("client proof mismatch")
			}
			key, err := s.VerifyServerProof(unhex(t, f.M2))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key, unhex(t, f.K)) {
				t.Fatal("shared key mismatch")
			}
			if _, err := s.VerifyServerProof(unhex(t, f.M2)); err == nil {
				t.Fatal("server proof reused")
			}
			if _, err := s.Respond(f.Password, challenge); err == nil {
				t.Fatal("session reused")
			}
		})
	}
}

func TestSRPRejectsBadProofAndConsumesSession(t *testing.T) {
	f := srpFixtures(t)[0]
	for _, proof := range [][]byte{nil, make([]byte, 33), make([]byte, 32)} {
		s, challenge := fixtureSession(t, f)
		if _, err := s.Respond(f.Password, challenge); err != nil {
			t.Fatal(err)
		}
		if key, err := s.VerifyServerProof(proof); key != nil || err == nil {
			t.Fatal("accepted invalid proof")
		}
		if key, err := s.VerifyServerProof(unhex(t, f.M2)); key != nil || err == nil {
			t.Fatal("accepted retry after failure")
		}
	}
	s, challenge := fixtureSession(t, f)
	if _, err := s.Respond("wrong-password", challenge); err != nil {
		t.Fatal(err)
	}
	if key, err := s.VerifyServerProof(unhex(t, f.M2)); key != nil || err == nil {
		t.Fatal("wrong password established key")
	}
}

func TestSRPRejectsBadChallenges(t *testing.T) {
	f := srpFixtures(t)[0]
	for _, bad := range [][]byte{nil, {0}, padSRP(srpN), make([]byte, 257)} {
		s, challenge := fixtureSession(t, f)
		challenge.ServerPublic = bad
		if _, err := s.Respond(f.Password, challenge); err == nil {
			t.Fatal("accepted invalid public key")
		}
		challenge.ServerPublic = unhex(t, f.B)
		if _, err := s.Respond(f.Password, challenge); err == nil {
			t.Fatal("reused failed session")
		}
	}
	s, challenge := fixtureSession(t, f)
	challenge.Scheme = "future-unknown"
	if _, err := s.Respond(f.Password, challenge); err == nil {
		t.Fatal("accepted unknown scheme")
	}
	var zero SRPSession
	if _, err := zero.Respond(f.Password, challenge); err == nil {
		t.Fatal("accepted zero session")
	}
}

func TestSRPFreshRandomSessionAndCopies(t *testing.T) {
	if _, err := NewSRPSession(""); err == nil {
		t.Fatal("accepted empty identity")
	}
	x, err := NewSRPSession("research@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	y, err := NewSRPSession("research@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if len(x.PublicKey()) != 256 || bytes.Equal(x.PublicKey(), y.PublicKey()) {
		t.Fatal("public key generation failed")
	}
	a := x.PublicKey()
	a[0] ^= 1
	if bytes.Equal(a, x.PublicKey()) {
		t.Fatal("public key aliases internal state")
	}
	if _, err := x.VerifyServerProof(make([]byte, 32)); err == nil {
		t.Fatal("verified before challenge")
	}
}
