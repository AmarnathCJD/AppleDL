package applemusic

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestPasswordIndependentVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/password.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Password, Salt, Derived string
		Iterations              int
		Scheme                  PasswordScheme
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		salt, err := hex.DecodeString(v.Salt)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DerivePassword(v.Password, salt, v.Iterations, v.Scheme)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != v.Derived {
			t.Errorf("%s/%d: derivation mismatch", v.Scheme, v.Iterations)
		}
	}
}

func TestPasswordRejectsInvalidParameters(t *testing.T) {
	for _, count := range []int{-1, 0, MaxPasswordIterations + 1} {
		if _, err := DerivePassword("fake", []byte("salt"), count, S2K); err == nil {
			t.Fatal("accepted invalid iteration count")
		}
	}
	if _, err := DerivePassword("fake", []byte("salt"), 1, "unknown"); err == nil {
		t.Fatal("accepted unknown scheme")
	}
	if _, err := DerivePassword("fake", nil, 1, S2K); err == nil {
		t.Fatal("accepted empty salt")
	}
}
