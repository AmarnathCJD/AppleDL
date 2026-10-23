package applemusic

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPETExpiry(t *testing.T) {
	for _, raw := range []string{`{"com.apple.gs.idms.pet":{"expiry":1792696890920,"duration":300}}`, `{}`, `{"com.apple.gs.idms.pet":{"expiry":0}}`, `{"com.apple.gs.idms.pet":{"expiry":"1792696890920"}}`, `{"com.apple.gs.idms.pet":{"expiry":1.5}}`, `{"com.apple.gs.idms.pet":{"expiry":9223372036854775807}}`} {
		r := &SRPExchangeResult{AccountData: map[string]json.RawMessage{"t": json.RawMessage(raw)}}
		expiry, err := r.PETExpiry()
		valid := strings.Contains(raw, `"duration"`)
		if (err == nil) != valid {
			t.Fatal("unexpected expiry validation result")
		}
		if valid && !expiry.Equal(time.UnixMilli(1792696890920)) {
			t.Fatal("expiry is not Unix milliseconds")
		}
	}
}

func TestPETExpiryIgnoresUnrelatedTokenFormats(t *testing.T) {
	r := &SRPExchangeResult{AccountData: map[string]json.RawMessage{"t": json.RawMessage(`{"other":{"expiry":"unknown"},"com.apple.gs.idms.pet":{"expiry":1792696890920}}`)}}
	expiry, err := r.PETExpiry()
	if err != nil || !expiry.Equal(time.UnixMilli(1792696890920)) {
		t.Fatal("unrelated token blocked PET expiry")
	}
}

func TestPETExtraction(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"nested token", `{"t":{"com.apple.gs.idms.pet":{"token":"test-pet","expires":123},"other":{"token":"ignored"}}}`, "test-pet"},
		{"opaque token preserved", `{"t":{"com.apple.gs.idms.pet":{"token":"a+b/= x"}}}`, "a+b/= x"},
		{"missing root", `{}`, ""},
		{"null root", `{"t":null}`, ""},
		{"array root", `{"t":[]}`, ""},
		{"missing entry", `{"t":{"other":{"token":"secret-token"}}}`, ""},
		{"flat token", `{"t":{"com.apple.gs.idms.pet":"secret-token"}}`, ""},
		{"null entry", `{"t":{"com.apple.gs.idms.pet":null}}`, ""},
		{"missing value", `{"t":{"com.apple.gs.idms.pet":{}}}`, ""},
		{"null value", `{"t":{"com.apple.gs.idms.pet":{"token":null}}}`, ""},
		{"number value", `{"t":{"com.apple.gs.idms.pet":{"token":123}}}`, ""},
		{"empty value", `{"t":{"com.apple.gs.idms.pet":{"token":""}}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var result PasswordExchangeResult
			if err := json.Unmarshal([]byte(tc.data), &result.AccountData); err != nil {
				t.Fatal(err)
			}
			got, err := result.PET()
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatal("unexpected PET extraction result")
			}
			if err != nil && strings.Contains(err.Error(), "secret-token") {
				t.Fatal("PET error leaked data")
			}
		})
	}
	var nilResult *PasswordExchangeResult
	if _, err := nilResult.PET(); err == nil {
		t.Fatal("nil result accepted")
	}
	malformed := &PasswordExchangeResult{AccountData: map[string]json.RawMessage{"t": json.RawMessage(`{"secret-token":`)}}
	if token, err := malformed.PET(); err == nil || token != "" || strings.Contains(err.Error(), "secret-token") {
		t.Fatal("malformed token map not rejected cleanly")
	}
}
