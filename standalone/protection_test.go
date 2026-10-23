package standalone

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStateProtectionTamperingAndPortability(t *testing.T) {
	dir := t.TempDir()
	plain := []byte("synthetic local credential")
	blob, err := protectState(dir, "device", plain, false)
	if err != nil {
		t.Fatal(err)
	}
	again, err := protectState(dir, "device", plain, false)
	if err != nil || bytes.Equal(blob, again) {
		t.Fatal("nonce was reused", err)
	}
	if bytes.Contains(blob, plain) {
		t.Fatal("plaintext stored")
	}
	for _, index := range []int{0, 8, len(blob) - 1} {
		bad := bytes.Clone(blob)
		bad[index] ^= 1
		if _, err := protectState(dir, "device", bad, true); err == nil {
			t.Fatal("tampering accepted")
		}
	}
	if _, err := protectState(dir, "commerce", blob, true); err == nil {
		t.Fatal("wrong state kind accepted")
	}
	other := t.TempDir()
	key, err := os.ReadFile(filepath.Join(dir, "state.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if err := os.WriteFile(filepath.Join(other, "state.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := protectState(other, "device", blob, true)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("copied state could not be opened", err)
	}
	key[0] ^= 1
	if err := os.WriteFile(filepath.Join(other, "state.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := protectState(other, "device", blob, true); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestStateKeyNeverResetForExistingState(t *testing.T) {
	for _, name := range []string{"device.state", "idms.state", "commerce.state"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := stateKey(dir, true); err == nil {
				t.Fatal("replacement key generated")
			}
			if _, err := os.Stat(filepath.Join(dir, "state.key")); !os.IsNotExist(err) {
				t.Fatal("key created")
			}
		})
	}
	for _, length := range []int{0, 31, 33} {
		dir := t.TempDir()
		path := filepath.Join(dir, "state.key")
		if err := os.WriteFile(path, make([]byte, length), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := stateKey(dir, true); err == nil {
			t.Fatal("damaged key replaced")
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) != length {
			t.Fatal("damaged key changed")
		}
	}
}
