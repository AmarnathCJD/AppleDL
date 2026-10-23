package applemusic

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
)

func TestCommerceObservationNeverCertifiesMediaAccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*CommerceResponse)
		want CommerceObservation
	}{
		{"issued with unresolved minus128", func(r *CommerceResponse) { r.Fields["status"] = int64(-128) }, CommerceCredentialReceived},
		{"issued with unfamiliar status", func(r *CommerceResponse) { r.Fields["status"] = "unknown" }, CommerceCredentialReceived},
		{"HTTP failure with fields", func(r *CommerceResponse) { r.HTTPStatus = 401 }, CommerceUnclassified},
		{"HTTP unknown", func(r *CommerceResponse) { r.HTTPStatus = 0 }, CommerceUnclassified},
		{"challenge with fields", func(r *CommerceResponse) { r.HTTPHeaders["x-apple-amd-action"] = []string{"SP"} }, CommerceUnclassified},
		{"location with fields", func(r *CommerceResponse) { r.HTTPHeaders.Set("Location", "https://example.invalid") }, CommerceUnclassified},
		{"failure with fields", func(r *CommerceResponse) { r.Fields["failureType"] = "-5000" }, CommerceUnclassified},
		{"error with fields", func(r *CommerceResponse) { r.Fields["errorCode"] = int64(-20101) }, CommerceUnclassified},
		{"message with fields", func(r *CommerceResponse) { r.Fields["customerMessage"] = "review account" }, CommerceUnclassified},
		{"empty token", func(r *CommerceResponse) { r.Fields["passwordToken"] = "" }, CommerceUnclassified},
		{"missing identity", func(r *CommerceResponse) { delete(r.Fields, "altDsid") }, CommerceUnclassified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &CommerceResponse{Fields: commerceAccountFields(), HTTPStatus: 200, HTTPHeaders: make(http.Header)}
			tc.edit(r)
			if r.Observation() != tc.want {
				t.Fatal("unexpected credential observation")
			}
		})
	}
	var absent *CommerceResponse
	if absent.Observation() != CommerceUnclassified {
		t.Fatal("nil response accepted")
	}
}

func TestCommerceResponseRedactionAndCleanup(t *testing.T) {
	data := []byte("sensitive bytes")
	fields := map[string]any{"nested": []any{data, map[string]any{"token": "sensitive"}}}
	headers := http.Header{"Set-Cookie": {"sensitive cookie"}}
	r := &CommerceResponse{Fields: fields, HTTPHeaders: headers, HTTPStatus: 200}
	if bytes.Contains([]byte(fmt.Sprintf("%v %+v %#v", r, r, r)), []byte("sensitive")) {
		t.Fatal("formatting leaked response")
	}
	r.Destroy()
	if len(fields) != 0 || len(headers) != 0 || !bytes.Equal(data, make([]byte, len(data))) || r.HTTPStatus != 0 {
		t.Fatal("cleanup retained owned values")
	}
	r.Destroy()
}
