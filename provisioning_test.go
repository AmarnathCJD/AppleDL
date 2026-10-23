package applemusic

import (
	"bytes"
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

func TestProvisioningWire(t *testing.T) {
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		t.Run(plist.FormatNames[format], func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-apple-plist" ||
					r.Header.Get("X-Test-Device") != r.URL.Path || r.Header.Get("User-Agent") != "test-app" {
					t.Error("unexpected method or device headers")
				}
				data, _ := io.ReadAll(r.Body)
				var envelope map[string]any
				if _, err := plist.Unmarshal(data, &envelope); err != nil {
					t.Error(err)
				}
				request := map[string]any{}
				response := map[string]any{"spim": "AAH+/w=="}
				if r.URL.Path == "/finish" {
					request["cpim"] = "Av8=" // string, never plist <data>
					response = map[string]any{"ptm": "A/4=", "tk": "BP0="}
				}
				if !reflect.DeepEqual(envelope, map[string]any{"Header": map[string]any{}, "Request": request}) {
					t.Error("provisioning plist envelope differs from the native request")
				}
				encoded, _ := plist.Marshal(map[string]any{"Response": response, "Unmapped": "preserved"}, format)
				w.Header().Set("X-Test-Transaction", "test-transaction")
				_, _ = w.Write(encoded)
			}))
			defer server.Close()
			client, _ := New(Config{HTTPClient: server.Client(), Headers: http.Header{"User-Agent": {"test-app"}}})
			start, err := client.StartProvisioning(context.Background(), server.URL+"/start", http.Header{"X-Test-Device": {"/start"}})
			if err != nil || !bytes.Equal(start.SPIM, []byte{0, 1, 254, 255}) {
				t.Fatalf("start result: %v", err)
			}
			finish, err := client.FinishProvisioning(context.Background(), server.URL+"/finish", []byte{2, 255}, http.Header{"X-Test-Device": {"/finish"}})
			if err != nil || !bytes.Equal(finish.PTM, []byte{3, 254}) || !bytes.Equal(finish.TK, []byte{4, 253}) {
				t.Fatalf("finish result: %v", err)
			}
			if requests != 2 || start.Envelope["Unmapped"] != "preserved" || finish.Envelope["Unmapped"] != "preserved" ||
				start.HTTPHeaders.Get("X-Test-Transaction") == "" || finish.HTTPHeaders.Get("X-Test-Transaction") == "" {
				t.Fatal("requests or preserved metadata differ")
			}
		})
	}
}

func TestProvisioningRejectsUnusableResponses(t *testing.T) {
	cases := []struct {
		name string
		step ProvisioningStep
		body any
	}{
		{"missing response", ProvisioningStart, map[string]any{}},
		{"response scalar", ProvisioningStart, map[string]any{"Response": "secret"}},
		{"challenge", ProvisioningStart, map[string]any{"Response": map[string]any{"Status": map[string]any{"ec": uint64(123), "em": "secret"}}}},
		{"spim data", ProvisioningStart, map[string]any{"Response": map[string]any{"spim": []byte{1}}}},
		{"empty spim", ProvisioningStart, map[string]any{"Response": map[string]any{"spim": ""}}},
		{"bad base64", ProvisioningStart, map[string]any{"Response": map[string]any{"spim": "%%%secret"}}},
		{"missing ptm", ProvisioningFinish, map[string]any{"Response": map[string]any{"tk": "AQ=="}}},
		{"missing tk", ProvisioningFinish, map[string]any{"Response": map[string]any{"ptm": "AQ=="}}},
		{"ptm number", ProvisioningFinish, map[string]any{"Response": map[string]any{"ptm": 2, "tk": "AQ=="}}},
		{"empty tk", ProvisioningFinish, map[string]any{"Response": map[string]any{"ptm": "AQ==", "tk": ""}}},
		{"partial base64", ProvisioningFinish, map[string]any{"Response": map[string]any{"ptm": "AQ==", "tk": "AQ==%%%"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, _ := plist.Marshal(tc.body, plist.XMLFormat)
			client, _ := New(Config{HTTPClient: &http.Client{Transport: commerceRoundTripper(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(encoded)), Header: http.Header{"X-Test-Challenge": {"secret"}}}, nil
			})}})
			var err error
			if tc.step == ProvisioningStart {
				_, err = client.StartProvisioning(context.Background(), "https://example.invalid/start", nil)
			} else {
				_, err = client.FinishProvisioning(context.Background(), "https://example.invalid/finish", []byte{1}, nil)
			}
			var responseErr *ProvisioningResponseError
			if !errors.As(err, &responseErr) || responseErr.Step != tc.step || responseErr.Envelope == nil || responseErr.HTTPHeaders.Get("X-Test-Challenge") != "secret" {
				t.Fatalf("expected preserved challenge, got %v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("response error exposed server data")
			}
		})
	}
}

type testProvisioningSession struct {
	finish func(context.Context, []byte, []byte) error
	close  func() error
}

func (s *testProvisioningSession) Finish(ctx context.Context, ptm, tk []byte) error {
	return s.finish(ctx, ptm, tk)
}
func (s *testProvisioningSession) Close() error { return s.close() }

func TestProvisionDeviceLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "start headers", "start request", "native start", "nil session", "empty cpim", "finish headers", "finish request", "native finish", "close", "finish and close", "cancel before", "cancel start headers", "cancel native start", "cancel finish response", "unsafe finish URL"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var events []string
			var buffers [][]byte
			providerErr, closeErr := errors.New("secret-provider"), errors.New("secret-cleanup")
			client, _ := New(Config{HTTPClient: &http.Client{Transport: commerceRoundTripper(func(r *http.Request) (*http.Response, error) {
				stage := strings.TrimPrefix(r.URL.Path, "/") + " request"
				events = append(events, stage)
				if r.GetBody != nil || r.Header.Get("X-Test-Step") != strings.TrimPrefix(r.URL.Path, "/") {
					t.Error("replayable request or stale headers")
				}
				if mode == stage {
					return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("secret-server"))}, nil
				}
				response := map[string]any{"spim": "AQ=="}
				if r.URL.Path == "/finish" {
					response = map[string]any{"ptm": "Aw==", "tk": "BA=="}
					if mode == "cancel finish response" {
						cancel()
					}
				}
				encoded, _ := plist.Marshal(map[string]any{"Response": response}, plist.XMLFormat)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(encoded))}, nil
			})}})
			options := ProvisioningOptions{
				StartURL: "https://example.invalid/start", FinishURL: "https://example.invalid/finish", DSID: AnisetteV3DSID,
				Headers: func(ctx context.Context, step ProvisioningStep) (http.Header, error) {
					stage := "start"
					if step == ProvisioningFinish {
						stage = "finish"
					}
					events = append(events, stage+" headers")
					if mode == stage+" headers" {
						return nil, providerErr
					}
					if mode == "cancel start headers" {
						cancel()
					}
					return http.Header{"X-Test-Step": {stage}, "Idempotency-Key": {"test"}}, nil
				},
				Native: func(ctx context.Context, dsid int64, spim []byte) ([]byte, NativeProvisioningSession, error) {
					events = append(events, "native start")
					if dsid != -2 || !bytes.Equal(spim, []byte{1}) {
						t.Error("wrong DSID or SPIM")
					}
					cpim := []byte{2}
					buffers = append(buffers, spim, cpim)
					session := &testProvisioningSession{
						finish: func(ctx context.Context, ptm, tk []byte) error {
							events = append(events, "native finish")
							if !bytes.Equal(ptm, []byte{3}) || !bytes.Equal(tk, []byte{4}) {
								t.Error("wrong PTM/TK order or decoding")
							}
							buffers = append(buffers, ptm, tk)
							if mode == "native finish" || mode == "finish and close" {
								return providerErr
							}
							return nil
						},
						close: func() error {
							events = append(events, "close")
							if mode == "close" || mode == "finish and close" {
								return closeErr
							}
							return nil
						},
					}
					if mode == "native start" {
						return cpim, session, providerErr
					}
					if mode == "nil session" {
						return cpim, nil, nil
					}
					if mode == "empty cpim" {
						return nil, session, nil
					}
					if mode == "cancel native start" {
						cancel()
					}
					return cpim, session, nil
				},
			}
			if mode == "cancel before" {
				cancel()
			}
			if mode == "unsafe finish URL" {
				options.FinishURL = "http://example.invalid/finish"
			}
			err := client.ProvisionDevice(ctx, options)
			if (err == nil) != (mode == "success") {
				t.Fatalf("unexpected result: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("error was not redacted")
			}
			want := []string{"start headers", "start request", "native start", "finish headers", "finish request", "native finish", "close"}
			switch mode {
			case "cancel before", "unsafe finish URL":
				want = nil
			case "start headers", "cancel start headers":
				want = want[:1]
			case "start request":
				want = want[:2]
			case "nil session":
				want = want[:3]
			case "native start", "empty cpim", "cancel native start":
				want = append(want[:3:3], "close")
			case "finish headers":
				want = append(want[:4:4], "close")
			case "finish request", "cancel finish response":
				want = append(want[:5:5], "close")
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("events %v; want %v", events, want)
			}
			if strings.HasPrefix(mode, "cancel") && !errors.Is(err, context.Canceled) {
				t.Error("cancellation not preserved")
			}
			if mode == "finish and close" && (!errors.Is(err, providerErr) || !errors.Is(err, closeErr)) {
				t.Error("primary or cleanup failure lost")
			}
			for i, b := range buffers {
				if mode == "empty cpim" && i == 1 {
					continue
				} // provider did not transfer this buffer
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Error("owned protocol buffer was not cleared")
				}
			}
		})
	}
}

func TestProvisioningTransportFailures(t *testing.T) {
	for _, mode := range []string{"redirect", "oversize", "malformed", "scalar", "empty cpim"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			client, _ := New(Config{HTTPClient: &http.Client{Transport: commerceRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				status, body := 200, "secret-bad-plist"
				header := http.Header{}
				switch mode {
				case "redirect":
					status = 307
					header.Set("Location", "https://example.invalid/secret")
				case "oversize":
					body = strings.Repeat("x", maxResponseBytes+1)
				case "scalar":
					data, _ := plist.Marshal("secret", plist.XMLFormat)
					body = string(data)
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}})
			cpim := []byte{1}
			if mode == "empty cpim" {
				cpim = nil
			}
			_, err := client.FinishProvisioning(context.Background(), "https://example.invalid/finish", cpim, nil)
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("expected redacted failure: %v", err)
			}
			if mode == "empty cpim" && calls != 0 || mode != "empty cpim" && calls != 1 {
				t.Fatal("unexpected request or replay")
			}
			var redirect *RedirectError
			if mode == "redirect" && !errors.As(err, &redirect) {
				t.Fatal("redirect was not preserved")
			}
		})
	}
}
