package standalone

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedStateRoundTripAndExclusiveOwner(t *testing.T) {
	dir := t.TempDir()
	s, state, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if second, _, e := openState(dir); e == nil {
		second.close()
		t.Fatal("second owner acquired device state")
	}
	id := state.AndroidID
	state.Files["/adi/test.bin"] = []byte("synthetic secret fixture")
	state.Modified["/adi/test.bin"] = 1700000000123456789
	if err := s.save(state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "device.state"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(id)) || bytes.Contains(raw, state.Files["/adi/test.bin"]) {
		t.Fatal("state file contains plaintext")
	}
	s.close()
	s2, loaded, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AndroidID != id || !bytes.Equal(loaded.Files["/adi/test.bin"], state.Files["/adi/test.bin"]) || loaded.Modified["/adi/test.bin"] != state.Modified["/adi/test.bin"] {
		t.Fatal("state was not preserved")
	}
	s2.close()
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(filepath.Join(dir, "device.state"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if s3, _, err := openState(dir); err == nil {
		s3.close()
		t.Fatal("corrupt state accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "device.state"))
	if !bytes.Equal(raw, after) {
		t.Fatal("corrupt existing state was replaced")
	}
}

func TestGoDeviceReopensAndRefusesUnprovisionedOTP(t *testing.T) {
	cfg := Config{StateDir: t.TempDir()}
	var previous string
	for range 2 {
		d, err := Open(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		id, err := d.StableID(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if previous != "" && id != previous {
			t.Fatal("identity changed on reopen")
		}
		previous = id
		for _, dsid := range []int64{-2, -1} {
			code, err := d.Status(context.Background(), dsid)
			if err != nil || code != -45061 {
				t.Fatalf("unexpected initial status %d: %v", code, err)
			}
		}
		if headers, err := d.AnisetteHeaders(context.Background(), -2); err == nil || headers != nil {
			t.Fatal("unprovisioned device returned OTP headers")
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMissingDevicePreservesRemainingAccountFiles(t *testing.T) {
	for _, name := range []string{"device.dpapi", "idms.dpapi", "commerce.dpapi", "idms.state", "commerce.state"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			before := []byte("synthetic existing account")
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			if s, _, err := openState(dir); err == nil {
				s.close()
				t.Fatal("new identity created over remaining account state")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("account state changed")
			}
			for _, unwanted := range []string{"device.state", "state.key", "device.lock"} {
				if _, err := os.Lstat(filepath.Join(dir, unwanted)); !os.IsNotExist(err) {
					t.Fatalf("left %s behind", unwanted)
				}
			}
		})
	}
}
