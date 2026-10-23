package applemusic

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"howett.net/plist"
)

func TestStoreWireRequestAndBinaryResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-apple-plist" || r.Header.Get("Accept") != "*/*" {
			t.Errorf("unexpected method or headers")
		}
		if r.Header.Get("X-Test-Identity") != "original" {
			t.Error("headers were not copied")
		}
		data, _ := io.ReadAll(r.Body)
		var got map[string]any
		if _, err := plist.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"appleId": "test@example.invalid", "password": "test-password", "guid": "test-guid", "attempt": "2", "rmp": "0", "createSession": "true", "why": "signIn"}
		if !reflect.DeepEqual(got, want) {
			t.Error("store plist fields or types differ")
		}
		body, _ := plist.Marshal(map[string]any{"dsPersonId": "123", "passwordToken": "test-token", "accountInfo": map[string]any{"name": "Test"}}, plist.BinaryFormat)
		w.Header().Set("X-Apple-Store-Front", "143441-1,29")
		w.Write(body)
	}))
	defer server.Close()
	headers := http.Header{"X-Test-Identity": {"original"}}
	client, err := New(Config{HTTPClient: server.Client(), Headers: headers})
	if err != nil {
		t.Fatal(err)
	}
	headers.Set("X-Test-Identity", "changed")
	result, err := client.AuthenticateStore(context.Background(), server.URL, StoreCredentials{"test@example.invalid", "test-password", "test-guid", 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.DSID != "123" || result.PasswordToken != "test-token" || result.HTTPHeaders.Get("X-Apple-Store-Front") == "" {
		t.Error("response fields missing")
	}
}

func TestRedirectNeverReplaysCredential(t *testing.T) {
	var redirected bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/?secret=do-not-log", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client, _ := New(Config{HTTPClient: server.Client()})
	_, err := client.AuthenticateStore(context.Background(), server.URL, StoreCredentials{"test", "password", "guid", 0})
	var redirect *RedirectError
	if !errors.As(err, &redirect) || redirect.StatusCode != 307 {
		t.Fatalf("expected redirect error: %v", err)
	}
	if redirected {
		t.Error("replayed credential to redirect target")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Error("redirect error leaked location")
	}
}

func TestResponseFailuresAreBoundedAndRedacted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"http", 401, "secret-token", "HTTP status 401"},
		{"malformed", 200, "<plist><secret-token>", "invalid authentication plist"},
		{"oversize", 200, strings.Repeat("x", maxResponseBytes+1), "exceeds size limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer server.Close()
			client, _ := New(Config{HTTPClient: server.Client()})
			_, err := client.AuthenticateStore(context.Background(), server.URL, StoreCredentials{"test", "password", "guid", 0})
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRejectUnsafeEndpoints(t *testing.T) {
	for _, endpoint := range []string{"http://example.invalid", "https://user:password@example.invalid", "https://example.invalid/#fragment", "/relative"} {
		if _, err := New(Config{GrandSlamURL: endpoint}); err == nil {
			t.Errorf("accepted %q", endpoint)
		}
	}
}

func TestCancellation(t *testing.T) {
	client, _ := New(Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.AuthenticateStore(ctx, "https://example.invalid", StoreCredentials{"test", "password", "guid", 0})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
