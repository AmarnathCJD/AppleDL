package standalone

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func exportedFixture(t *testing.T) (string, *sessionSnapshot) {
	t.Helper()
	ctx := context.Background()
	d, err := Open(ctx, Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
	})
	id, err := d.StableID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := fixtureAccount()
	defer a.Destroy()
	a.DeviceID = id
	a.Exchange.AccountData["adsid"] = json.RawMessage(`"synthetic-alt"`)
	if err := d.SaveIdMSAccount(ctx, a.Username, a.Exchange); err != nil {
		t.Fatal(err)
	}
	c := fixtureCommerce(t)
	defer c.Destroy()
	c.HTTPHeaders.Set("X-Set-Apple-Store-Front", "143441-1,32")
	r, err := c.Response()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	if err := d.SaveCommerceResponse(ctx, c.Username, r); err != nil {
		t.Fatal(err)
	}
	encoded, err := d.ExportSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := decodeSession(encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(snapshot.destroy)
	return encoded, snapshot
}

func TestSessionSnapshotRoundTrip(t *testing.T) {
	encoded, want := exportedFixture(t)
	d, err := RestoreSession(context.Background(), Config{StateDir: filepath.Join(t.TempDir(), "restored")}, encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	restored, err := d.ExportSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeSession(restored)
	if err != nil {
		t.Fatal(err)
	}
	defer got.destroy()
	if !reflect.DeepEqual(want, got) {
		t.Fatal("device, credentials, receipt times or response types changed")
	}
}

func TestSessionSnapshotCorruptionIdentityAndExistingDirectory(t *testing.T) {
	encoded, snapshot := exportedFixture(t)
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "preserved")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if d, err := RestoreSession(context.Background(), Config{StateDir: dir}, encoded); err == nil {
		d.Close()
		t.Fatal("existing directory accepted")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "unchanged" {
		t.Fatal("existing directory changed")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(encoded)
	raw[len(raw)/2] ^= 1
	if s, err := decodeSession(base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		s.destroy()
		t.Fatal("corrupt portable envelope accepted")
	}
	for _, mutate := range []func(*sessionSnapshot){
		func(s *sessionSnapshot) { s.Account.DeviceID = "fedcba9876543210" },
		func(s *sessionSnapshot) { s.Account.Username = "other@example.invalid" },
		func(s *sessionSnapshot) { s.Account.Exchange.AccountData["adsid"] = json.RawMessage(`"other-account"`) },
		func(s *sessionSnapshot) { s.Version = 2 },
	} {
		b, _ := json.Marshal(snapshot)
		var changed sessionSnapshot
		if err := json.Unmarshal(b, &changed); err != nil {
			t.Fatal(err)
		}
		clear(b)
		mutate(&changed)
		if validSessionSnapshot(&changed) {
			changed.destroy()
			t.Fatal("invalid binding accepted")
		}
		changed.destroy()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	newDir := filepath.Join(dir, "cancelled")
	if _, err := RestoreSession(ctx, Config{StateDir: newDir}, encoded); err == nil {
		t.Fatal("cancelled restore succeeded")
	}
	if _, err := os.Stat(newDir); !os.IsNotExist(err) {
		t.Fatal("cancelled restore wrote state")
	}
}
