package applemusic

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestSPDJavaFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/spd.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name, Key, Plain, Encrypted string
		Valid                       bool
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			key, encrypted := unhex(t, f.Key), unhex(t, f.Encrypted)
			original := bytes.Clone(encrypted)
			got, err := DecryptSPD(key, encrypted)
			if !f.Valid {
				if err == nil || got != nil {
					t.Fatal("accepted invalid data")
				}
				if err.Error() != "invalid encrypted account data" {
					t.Fatal("unredacted error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want map[string]json.RawMessage
			if err := json.Unmarshal(unhex(t, f.Plain), &want); err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Fatal("dictionary size mismatch")
			}
			for k, v := range want {
				if !bytes.Equal(got[k], v) {
					t.Fatalf("field %q mismatch", k)
				}
			}
			if !bytes.Equal(original, encrypted) {
				t.Fatal("ciphertext mutated")
			}
		})
	}
}

func TestSPDInvalidLengths(t *testing.T) {
	for _, pair := range [][2]int{{0, 16}, {33, 16}, {32, 0}, {32, 15}, {32, 17}, {32, maxResponseBytes + 16}} {
		if _, err := DecryptSPD(make([]byte, pair[0]), make([]byte, pair[1])); err == nil {
			t.Fatal("accepted invalid length")
		}
	}
}
