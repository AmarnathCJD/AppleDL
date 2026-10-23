package applemusic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"howett.net/plist"
)

func TestCommerceWireTypesAndPreparedBytes(t *testing.T) {
	for _, guid := range []string{"test-guid", ""} {
		t.Run("guid="+guid, func(t *testing.T) {
			var prepared []byte
			requests, preparations := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				digest := sha256.Sum256(data)
				if !bytes.Equal(data, prepared) || r.Header.Get("X-Test-Body-Digest") != hex.EncodeToString(digest[:]) {
					t.Error("prepared and transmitted bytes differ")
				}
				if r.Method != "POST" || r.Header.Get("Content-Type") != commerceContentType ||
					r.Header.Get("Accept") != "*/*" || r.Header.Get("X-Apple-Ignore-Account-Conversion") != "true" ||
					r.Header.Get("X-Test-Device") != "fresh" || r.Header.Get("User-Agent") != "test-agent" {
					t.Error("unexpected prepared method or headers")
				}
				var fields map[string]any
				if _, err := plist.Unmarshal(data, &fields); err != nil {
					t.Error(err)
				}
				want := map[string]any{"appleId": "test@example.invalid", "password": "test-pet", "createSession": true, "rmp": uint64(0)}
				if guid != "" {
					want["guid"] = guid
				}
				if !reflect.DeepEqual(fields, want) {
					t.Error("modern commerce plist fields or types differ")
				}
				response, _ := plist.Marshal(map[string]any{
					"dsPersonId": "123", "passwordToken": "test-password-token",
					"accountInfo": map[string]any{"appleId": "test@example.invalid"},
					"unmapped":    []string{"preserved"},
				}, plist.BinaryFormat)
				w.Header().Set("X-Apple-Store-Front", "143441-1,29")
				w.Header().Add("Set-Cookie", "test=value; Secure")
				_, _ = w.Write(response)
			}))
			defer server.Close()
			client, _ := New(Config{HTTPClient: server.Client(), Headers: http.Header{"User-Agent": {"test-agent"}}})
			options := CommerceOptions{Headers: http.Header{"X-Test-Device": {"initial"}}, IgnoreAccountConversion: true}
			options.PrepareRequest = func(ctx context.Context, req CommerceRequest) (http.Header, error) {
				preparations++
				if req.Method != "POST" || req.URL != server.URL || req.Headers.Get("X-Test-Device") != "initial" ||
					req.Headers.Get("X-Apple-Ignore-Account-Conversion") != "true" {
					t.Error("preparer did not see constructed request")
				}
				prepared = append([]byte(nil), req.Body...)
				digest := sha256.Sum256(req.Body)
				req.Headers.Set("X-Test-Body-Digest", hex.EncodeToString(digest[:]))
				req.Headers.Set("X-Test-Device", "fresh")
				// Mutating the snapshot must not alter the original serialized body.
				clear(req.Body)
				req.Method, req.URL = "GET", "https://example.invalid"
				return req.Headers, nil
			}
			response, err := client.AuthenticatePET(context.Background(), server.URL, PETCredentials{"test@example.invalid", "test-pet", guid}, options)
			if err != nil {
				t.Fatal(err)
			}
			if requests != 1 || preparations != 1 || options.Headers.Get("X-Test-Device") != "initial" {
				t.Fatal("unexpected call count or caller headers were mutated")
			}
			if response.HTTPStatus != 200 || response.Fields["passwordToken"] != "test-password-token" || response.Fields["unmapped"] == nil ||
				response.HTTPHeaders.Get("Set-Cookie") == "" || response.HTTPHeaders.Get("X-Apple-Store-Front") == "" {
				t.Fatal("response data not preserved")
			}
		})
	}
}

type commerceRoundTripper func(*http.Request) (*http.Response, error)

func (f commerceRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCommercePreparationFailureDoesNotSend(t *testing.T) {
	for _, mode := range []string{"missing", "error", "nil headers", "content type", "duplicate", "encoding", "length", "host", "cancel before", "cancel during", "unsafe endpoint", "missing PET"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, preparations := 0, 0
			client, _ := New(Config{HTTPClient: &http.Client{Transport: commerceRoundTripper(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected transport call")
			})}})
			providerErr := errors.New("secret-provider-diagnostics")
			options := CommerceOptions{PrepareRequest: func(ctx context.Context, req CommerceRequest) (http.Header, error) {
				preparations++
				switch mode {
				case "error":
					return nil, providerErr
				case "nil headers":
					return nil, nil
				case "content type":
					req.Headers.Set("Content-Type", "application/json")
				case "duplicate":
					req.Headers["content-type"] = []string{commerceContentType}
				case "encoding":
					req.Headers.Set("Content-Encoding", "gzip")
				case "length":
					req.Headers.Set("Content-Length", "1")
				case "host":
					req.Headers.Set("Host", "other.invalid")
				case "cancel during":
					cancel()
				}
				return req.Headers, nil
			}}
			endpoint := "https://example.invalid/authenticate"
			credentials := PETCredentials{"test", "secret-pet", "guid"}
			early := false
			switch mode {
			case "missing":
				options.PrepareRequest, early = nil, true
			case "cancel before":
				cancel()
				early = true
			case "unsafe endpoint":
				endpoint, early = "http://example.invalid", true
			case "missing PET":
				credentials.PET, early = "", true
			}
			result, err := client.AuthenticatePET(ctx, endpoint, credentials, options)
			if err == nil || result != nil || calls != 0 || (early && preparations != 0) || (!early && preparations != 1) {
				t.Fatalf("unexpected failure handling: %v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("error exposed provider or credential data")
			}
			if mode == "error" && !errors.Is(err, providerErr) {
				t.Fatal("provider error cause lost")
			}
			if strings.HasPrefix(mode, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation not preserved")
			}
		})
	}
}

func TestCommerceResponsesRemainExplicit(t *testing.T) {
	for _, mode := range []string{"failure dictionary", "redirect", "http error", "malformed", "array", "oversize", "transport failure"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			client, _ := New(Config{HTTPClient: &http.Client{Transport: commerceRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.GetBody != nil {
					t.Error("credential body is replayable")
				}
				status, header := 200, make(http.Header)
				header.Set("X-Apple-AMD-Action", "SP")
				header.Set("X-Apple-AMD-Data", "secret-challenge")
				body, _ := plist.Marshal(map[string]any{"failureType": "challenge", "customerMessage": "secret-response"}, plist.XMLFormat)
				switch mode {
				case "redirect":
					status = 307
					header.Set("Location", "https://other.invalid/?secret-redirect")
				case "http error":
					status = 401
				case "malformed":
					body = []byte("secret-response")
				case "array":
					body, _ = plist.Marshal([]string{"secret-response"}, plist.BinaryFormat)
				case "oversize":
					body = bytes.Repeat([]byte("x"), maxResponseBytes+1)
				case "transport failure":
					return nil, errors.New("secret-transport")
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
			})}})
			options := CommerceOptions{PrepareRequest: func(_ context.Context, req CommerceRequest) (http.Header, error) {
				// Configuration can select no signature. A fixed signature header
				// is deliberately not required by the library.
				req.Headers.Set("Idempotency-Key", "test-only")
				return req.Headers, nil
			}}
			response, err := client.AuthenticatePET(context.Background(), "https://example.invalid/authenticate", PETCredentials{"test", "test-pet", ""}, options)
			if calls != 1 {
				t.Fatal("request was repeated")
			}
			if response != nil {
				wantStatus := 200
				if mode == "redirect" {
					wantStatus = 307
				}
				if mode == "http error" {
					wantStatus = 401
				}
				if response.HTTPStatus != wantStatus {
					t.Fatal("HTTP status not preserved")
				}
			}
			if mode == "failure dictionary" {
				if err != nil || response == nil || response.Fields["failureType"] != "challenge" {
					t.Fatal("HTTP 200 failure dictionary not preserved")
				}
				return
			}
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unexpected error handling: %v", err)
			}
			if mode == "oversize" || mode == "transport failure" {
				if response != nil {
					t.Fatal("unexpected response without headers")
				}
			} else if response == nil || response.Fields != nil || response.HTTPHeaders.Get("X-Apple-AMD-Data") != "secret-challenge" {
				t.Fatal("error response did not retain challenge headers")
			}
			if mode == "redirect" {
				var redirect *RedirectError
				if !errors.As(err, &redirect) || redirect.StatusCode != 307 {
					t.Fatal("redirect not exposed")
				}
			}
			if mode == "http error" {
				var status *HTTPError
				if !errors.As(err, &status) || status.StatusCode != 401 {
					t.Fatal("HTTP failure not exposed")
				}
			}
		})
	}
}
