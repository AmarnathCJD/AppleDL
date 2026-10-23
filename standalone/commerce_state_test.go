package standalone

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/AmarnathCJD/AppleDL"
	"howett.net/plist"
)

func fixtureCommerce(t *testing.T) *SavedCommerceResponse {
	t.Helper()
	fields, err := plist.Marshal(map[string]any{
		"status": int64(-128), "accountInfo": map[string]any{"appleId": "fixture@example.invalid"},
		"dsPersonId": "123", "altDsid": "synthetic-alt", "passwordToken": "synthetic-secret",
		"future": map[string]any{"binary": []byte{1, 2, 3}, "list": []any{true, "retained"}},
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	return &SavedCommerceResponse{Version: 1, DeviceID: "0123456789abcdef", Username: "fixture@example.invalid",
		ObtainedAt: time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), HTTPStatus: 200, FieldsPlist: fields,
		HTTPHeaders: http.Header{"Set-Cookie": {"session=synthetic-cookie; Secure; HttpOnly", "other=synthetic-second; Path=/"}}}
}

func TestCommerceSnapshotEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := fixtureCommerce(t)
	defer s.Destroy()
	if err := saveCommerceSnapshot(dir, s); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "commerce.state"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{s.Username, s.DeviceID, "synthetic-secret", "synthetic-cookie", "synthetic-second"} {
		if bytes.Contains(raw, []byte(secret)) || bytes.Contains([]byte(fmt.Sprintf("%v %+v %#v", s, s, s)), []byte(secret)) {
			t.Fatal("plaintext exposed")
		}
	}
	got, err := loadCommerceSnapshot(dir, s.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()
	if !reflect.DeepEqual(s, got) {
		t.Fatal("snapshot lost metadata or response bytes")
	}
	r, err := got.Response()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	want, err := s.Response()
	if err != nil {
		t.Fatal(err)
	}
	defer want.Destroy()
	if !reflect.DeepEqual(r, want) || len(r.HTTPHeaders.Values("Set-Cookie")) != 2 || r.Observation() != applemusic.CommerceCredentialReceived {
		t.Fatal("response types, cookies or observation did not survive")
	}
	// Issued credentials do not upgrade the unknown wire status to success.
	if v, ok := r.Fields["status"].(int64); !ok || v != -128 {
		t.Fatal("plist integer changed")
	}
	if other, err := loadCommerceSnapshot(dir, "other-device"); err == nil || other != nil {
		t.Fatal("wrong device accepted")
	}
	// Unclassified responses must also reopen without being upgraded.
	r.Fields["errorCode"] = int64(-20101)
	s.FieldsPlist, err = plist.Marshal(r.Fields, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveCommerceSnapshot(dir, s); err != nil {
		t.Fatal(err)
	}
	updated, err := loadCommerceSnapshot(dir, s.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer updated.Destroy()
	u, err := updated.Response()
	if err != nil {
		t.Fatal(err)
	}
	defer u.Destroy()
	if u.Observation() != applemusic.CommerceUnclassified {
		t.Fatal("unclassified evidence upgraded")
	}
}

func TestCommerceSnapshotRejectsCorruptionAndInvalidReplacement(t *testing.T) {
	dir := t.TempDir()
	s := fixtureCommerce(t)
	defer s.Destroy()
	if err := saveCommerceSnapshot(dir, s); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "commerce.state")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*SavedCommerceResponse){func(s *SavedCommerceResponse) { s.Version = 2 }, func(s *SavedCommerceResponse) { s.HTTPStatus = 401 }, func(s *SavedCommerceResponse) { s.FieldsPlist = []byte("invalid") }} {
		bad := *s
		edit(&bad)
		if saveCommerceSnapshot(dir, &bad) == nil {
			t.Fatal("invalid replacement accepted")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("failed save changed existing state")
		}
	}
	before[len(before)/2] ^= 1
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadCommerceSnapshot(dir, s.DeviceID); err == nil || got != nil {
		t.Fatal("corrupt state accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed load changed state")
	}
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadCommerceSnapshot(dir, s.DeviceID); err == nil || got != nil {
		t.Fatal("plaintext state accepted")
	}
	files, err := filepath.Glob(filepath.Join(dir, ".commerce-*.tmp"))
	if err != nil || len(files) != 0 {
		t.Fatal("temporary snapshot left behind")
	}
}

func TestCommerceSnapshotDestroy(t *testing.T) {
	s := fixtureCommerce(t)
	data, headers := s.FieldsPlist, s.HTTPHeaders
	s.Destroy()
	if !bytes.Equal(data, make([]byte, len(data))) || len(headers) != 0 || s.Username != "" {
		t.Fatal("snapshot retained owned secrets")
	}
	s.Destroy()
	var absent *SavedCommerceResponse
	absent.Destroy()
}
