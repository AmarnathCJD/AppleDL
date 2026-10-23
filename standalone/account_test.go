package standalone

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/AmarnathCJD/AppleDL"
)

func fixtureAccount() *SavedIdMSAccount {
	return &SavedIdMSAccount{
		Version: 1, DeviceID: "0123456789abcdef", Username: "fixture@example.invalid",
		ObtainedAt: time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC),
		Exchange: &applemusic.SRPExchangeResult{
			AccountData: map[string]json.RawMessage{"t": json.RawMessage(`{"com.apple.gs.idms.pet":{"token":"synthetic-pet-secret"}}`)},
			Response: map[string]json.RawMessage{
				"M2": json.RawMessage(`"synthetic-proof"`), "spd": json.RawMessage(`"synthetic-spd"`),
				"Status": json.RawMessage(`{"ec":0,"au":"secondaryAuth","challenge":"synthetic-challenge"}`),
			},
			TransactionID: "synthetic-transaction", NP: []byte("synthetic-np"),
			HTTPHeaders: http.Header{"Set-Cookie": {"synthetic-cookie"}},
		},
	}
}

func TestAccountSnapshotEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a := fixtureAccount()
	defer a.Destroy()
	if err := saveAccount(dir, a); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "idms.state")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{a.DeviceID, a.Username, "synthetic-pet-secret", "synthetic-cookie", "synthetic-challenge"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("snapshot contains plaintext")
		}
		for _, v := range []any{a, a.Exchange} {
			if bytes.Contains([]byte(fmt.Sprintf("%v %+v %#v", v, v, v)), []byte(secret)) {
				t.Fatal("formatting exposes snapshot")
			}
		}
	}
	loaded, err := loadAccount(dir, a.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Destroy()
	if !reflect.DeepEqual(a, loaded) {
		t.Fatal("snapshot lost metadata, headers or challenge fields")
	}
	if pet, err := loaded.Exchange.PET(); err != nil || pet != "synthetic-pet-secret" {
		t.Fatal("PET did not round trip")
	}
	if other, err := loadAccount(dir, "another-device"); err == nil || other != nil {
		t.Fatal("cross-device snapshot accepted")
	}
	// Replacing a saved snapshot must leave a complete decryptable version.
	a.Exchange.NP = []byte("replacement")
	if err := saveAccount(dir, a); err != nil {
		t.Fatal(err)
	}
	replaced, err := loadAccount(dir, a.DeviceID)
	if err != nil || !bytes.Equal(replaced.Exchange.NP, a.Exchange.NP) {
		t.Fatal("atomic replacement failed")
	}
	replaced.Destroy()
}

func TestAccountSnapshotRejectsCorruptionAndInvalidReplacement(t *testing.T) {
	dir := t.TempDir()
	a := fixtureAccount()
	defer a.Destroy()
	if err := saveAccount(dir, a); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "idms.state")
	before, _ := os.ReadFile(path)
	a.Version = 2
	if err := saveAccount(dir, a); err == nil {
		t.Fatal("unknown snapshot version accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed save changed existing snapshot")
	}
	before[len(before)/2] ^= 1
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := loadAccount(dir, a.DeviceID); err == nil || loaded != nil {
		t.Fatal("corrupt snapshot accepted")
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed load changed existing snapshot")
	}
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := loadAccount(dir, a.DeviceID); err == nil || loaded != nil {
		t.Fatal("plaintext accepted")
	}
}

func TestAccountDestroyClearsOwnedBuffers(t *testing.T) {
	a := fixtureAccount()
	fields, headers, np := a.Exchange.AccountData, a.Exchange.HTTPHeaders, a.Exchange.NP
	token := fields["t"]
	a.Destroy()
	if a.Exchange != nil || a.Username != "" || len(fields) != 0 || len(headers) != 0 ||
		!bytes.Equal(token, make([]byte, len(token))) || !bytes.Equal(np, make([]byte, len(np))) {
		t.Fatal("owned sensitive buffers not cleared")
	}
	a.Destroy()
	var absent *SavedIdMSAccount
	absent.Destroy()
}
