package applemusic

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestGrandSlamWireAndSRP(t *testing.T) {
	for _, f := range srpFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			s, _ := fixtureSession(t, f)
			const continuation = "opaque:+/== text"
			step := 0
			encode := func(hex string) string { return base64.StdEncoding.EncodeToString(unhex(t, hex)) }
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				step++
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json; charset=UTF-8" {
					t.Error("unexpected method or content type")
				}
				if r.Header.Get("X-Test-Device") != []string{"", "init-device", "complete-device"}[step] {
					t.Error("per-step device headers missing")
				}
				var got map[string]any
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				request := map[string]any{"cpd": map[string]any{"bootstrap": true, "ckauth": false, "ckgen": true, "loc": "en_US"}, "u": f.Username}
				var response map[string]any
				if step == 1 {
					request["o"], request["A2k"], request["ps"] = "init", encode(f.A), []any{"s2k", "s2k_fo"}
					response = map[string]any{"s": encode(f.Salt), "B": encode(f.B), "sp": f.Scheme, "i": f.Iterations, "c": continuation, "ptxid": "synthetic-transaction"}
				} else {
					request["o"], request["M1"], request["c"] = "complete", encode(f.M1), continuation
					// The ciphertext is a wire-shape placeholder, not a login fixture.
					response = map[string]any{"M2": encode(f.M2), "np": "AQID", "spd": base64.StdEncoding.EncodeToString(make([]byte, 16))}
				}
				want := map[string]any{"Header": map[string]any{"v": "1"}, "Request": request}
				if !reflect.DeepEqual(got, want) {
					t.Error("request fields, types or proof differ from native wire format and independent fixture")
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"Response": response})
			}))
			defer server.Close()
			c, err := New(Config{HTTPClient: server.Client(), GrandSlamURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			options := GrandSlamOptions{Locale: "en_US", CKGen: true, Headers: http.Header{"X-Test-Device": {"init-device"}}}
			init, err := c.InitSRP(context.Background(), f.Username, s.PublicKey(), options)
			if err != nil {
				t.Fatal(err)
			}
			m1, err := s.Respond(f.Password, init.Challenge)
			if err != nil {
				t.Fatal(err)
			}
			options.Headers.Set("X-Test-Device", "complete-device")
			complete, err := c.CompleteSRP(context.Background(), f.Username, init.Continuation, m1, options)
			if err != nil {
				t.Fatal(err)
			}
			key, err := s.VerifyServerProof(complete.ServerProof)
			if err != nil {
				t.Fatal(err)
			}
			if step != 2 || !bytes.Equal(key, unhex(t, f.K)) || !bytes.Equal(complete.NP, []byte{1, 2, 3}) {
				t.Fatal("exchange result differs from independent fixture")
			}
		})
	}
}

func TestGrandSlamRejectsMalformedResponses(t *testing.T) {
	f := srpFixtures(t)[0]
	for _, body := range []string{
		`null`, `{}`, `{"Response":null}`, `{"Response":[]}`, `{"Response":{}}`,
		`{"Response":{"s":[1,2],"B":"AQ==","sp":"s2k","i":1,"c":"opaque","ptxid":"t"}}`,
		`{"Response":{"s":"@@@secret@@","B":"AQ==","sp":"s2k","i":1,"c":"opaque","ptxid":"t"}}`,
		`{"Response":{"s":"AQ==","B":"AQ==","sp":"s2k","i":1000001,"c":"opaque","ptxid":"t"}}`,
		`{"Response":{"s":"AQ==","B":"AQ==","sp":"s2k","i":"1","c":"opaque","ptxid":"t"}}`,
		`{"Response":{"s":"AQ==","B":"AQ==","sp":"s2k","i":null,"c":"opaque","ptxid":"t"}}`,
		`{"Response":{"s":"AQ==","B":"AQ==","sp":"future","i":1,"c":"opaque","ptxid":"t"}}`,
		`{"Response":{"Status":{"ec":-1,"em":"secret-account"}}}`,
		`{"Response":{"secret-account":`,
		strings.Repeat("x", maxResponseBytes+1),
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test-Continuation", "synthetic-continuation")
			io.WriteString(w, body)
		}))
		c, _ := New(Config{HTTPClient: server.Client(), GrandSlamURL: server.URL})
		_, err := c.InitSRP(context.Background(), f.Username, unhex(t, f.A), GrandSlamOptions{Locale: "en_US"})
		server.Close()
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("expected a redacted error, got %v", err)
		}
		if strings.Contains(body, `"Status"`) {
			var responseError *GrandSlamResponseError
			if !errors.As(err, &responseError) || responseError.Response["Status"] == nil || responseError.HTTPHeaders.Get("X-Test-Continuation") != "synthetic-continuation" {
				t.Fatal("lost server response for caller inspection")
			}
		}
	}
}

func TestGrandSlamCompleteRejectsMalformedProofData(t *testing.T) {
	for _, body := range []string{
		`{"Response":{"M2":null,"np":"","spd":"AAAAAAAAAAAAAAAAAAAAAA=="}}`,
		`{"Response":{"M2":[1,2,3],"np":"","spd":"AAAAAAAAAAAAAAAAAAAAAA=="}}`,
		`{"Response":{"M2":"AQ==","np":null,"spd":"AAAAAAAAAAAAAAAAAAAAAA=="}}`,
		`{"Response":{"M2":"AQ==","np":"","spd":"AQ=="}}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		c, _ := New(Config{HTTPClient: server.Client(), GrandSlamURL: server.URL})
		_, err := c.CompleteSRP(context.Background(), "test@example.invalid", "c", []byte{1}, GrandSlamOptions{Locale: "en_US"})
		server.Close()
		if err == nil {
			t.Fatal("accepted malformed completion")
		}
	}
}
