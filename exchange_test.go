package applemusic

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialExchangeAndFailureBoundaries(t *testing.T) {
	data, err := os.ReadFile("testdata/exchange-spd.json")
	if err != nil {
		t.Fatal(err)
	}
	var encryptedFixtures []struct{ Name, Key, Plain, Encrypted string }
	if err := json.Unmarshal(data, &encryptedFixtures); err != nil {
		t.Fatal(err)
	}
	for i, f := range srpFixtures(t) {
		if i >= len(encryptedFixtures) || encryptedFixtures[i].Name != f.Name || encryptedFixtures[i].Key != f.K {
			t.Fatal("Java SPD fixture does not match the Python server key")
		}
		modes := []string{"success"}
		if i == 0 {
			modes = append(modes, "bad-proof", "bad-ciphertext", "provider-error", "empty-headers", "challenge", "cancel")
		}
		for _, mode := range modes {
			for _, kind := range []string{"password", "continuation-key"} {
				t.Run(f.Name+"/"+mode+"/"+kind, func(t *testing.T) {
					ckAuth := kind == "continuation-key"
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					session, _ := fixtureSession(t, f)
					var providerCalls []SRPStep
					requests := 0
					providerErr := errors.New("secret device diagnostics")
					options := PasswordExchangeOptions{Locale: "en_US", DeviceHeaders: func(ctx context.Context, step SRPStep) (http.Header, error) {
						providerCalls = append(providerCalls, step)
						if step == SRPComplete {
							if mode == "provider-error" {
								return nil, providerErr
							}
							if mode == "empty-headers" {
								return nil, nil
							}
							if mode == "cancel" {
								cancel()
								return nil, ctx.Err()
							}
						}
						return http.Header{"X-Test-Step": {string(step)}}, nil
					}}
					server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests++
						var body struct {
							Request struct {
								Operation    string `json:"o"`
								Continuation string `json:"c"`
								Proof        []byte `json:"M1"`
								CPD          struct {
									Bootstrap, CKAuth, CKGen bool
									Loc                      string
								} `json:"cpd"`
							} `json:"Request"`
						}
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
							w.WriteHeader(400)
							return
						}
						q := body.Request
						if !q.CPD.Bootstrap || q.CPD.CKAuth != ckAuth || q.CPD.CKGen == ckAuth || q.CPD.Loc != "en_US" || r.Header.Get("X-Test-Step") != q.Operation {
							t.Error("credential flags, locale or fresh device headers were lost")
						}
						response := map[string]any{}
						if requests == 1 {
							if q.Operation != "init" {
								t.Error("first request is not init")
							}
							response = map[string]any{"s": unhex(t, f.Salt), "B": unhex(t, f.B), "sp": f.Scheme, "i": f.Iterations, "c": "opaque:+/== text", "ptxid": "fixture-transaction"}
						} else {
							if requests != 2 || q.Operation != "complete" || q.Continuation != "opaque:+/== text" || !reflect.DeepEqual(q.Proof, unhex(t, f.M1)) {
								t.Error("completion differs from independent SRP fixture")
							}
							m2 := unhex(t, f.M2)
							spd := unhex(t, encryptedFixtures[i].Encrypted)
							if mode == "bad-proof" {
								m2[0] ^= 1
							}
							if mode == "bad-proof" || mode == "bad-ciphertext" {
								spd = make([]byte, 16)
							}
							response = map[string]any{"M2": m2, "np": []byte{1, 2, 3}, "spd": spd}
							response["Status"] = map[string]any{"ec": 0, "au": "synthetic-status", "opaque": "secret continuation"}
							if mode == "challenge" {
								response = map[string]any{"Status": map[string]any{"ec": -1, "em": "secret account challenge"}}
							}
						}
						w.Header().Set("X-Test-Response", q.Operation)
						json.NewEncoder(w).Encode(map[string]any{"Response": response})
					}))
					defer server.Close()
					client, err := New(Config{HTTPClient: server.Client(), GrandSlamURL: server.URL})
					if err != nil {
						t.Fatal(err)
					}
					// The independent fixture string is also a synthetic CK credential.
					result, err := client.exchangeCredential(ctx, f.Username, f.Password, options, session, ckAuth)
					if session.private != nil || session.key != nil || session.m2 != nil || session.stage != 2 {
						t.Fatal("session was not discarded after exchange")
					}
					if !reflect.DeepEqual(providerCalls, []SRPStep{SRPInit, SRPComplete}) {
						t.Fatal("device provider call sequence changed")
					}
					if mode == "success" {
						if err != nil {
							t.Fatal(err)
						}
						var want map[string]json.RawMessage
						json.Unmarshal(unhex(t, encryptedFixtures[i].Plain), &want)
						if requests != 2 || !reflect.DeepEqual(result.AccountData, want) || result.TransactionID != "fixture-transaction" || result.HTTPHeaders.Get("X-Test-Response") != "complete" || !reflect.DeepEqual(result.NP, []byte{1, 2, 3}) {
							t.Fatal("exchange lost decoded account data or response metadata")
						}
						if !strings.Contains(string(result.Response["Status"]), "secret continuation") {
							t.Fatal("verified exchange discarded the server status or continuation")
						}
						return
					}
					if err == nil || result != nil || strings.Contains(err.Error(), "secret") {
						t.Fatal("failed exchange exposed data or returned success")
					}
					var exchangeErr *ExchangeError
					if !errors.As(err, &exchangeErr) {
						t.Fatal("lost exchange stage")
					}
					wantStage := map[string]string{"bad-proof": "server proof", "bad-ciphertext": "account data", "challenge": "complete", "provider-error": "complete headers", "empty-headers": "complete headers", "cancel": "complete headers"}[mode]
					if exchangeErr.Stage != wantStage {
						t.Fatalf("failed at %s, want %s", exchangeErr.Stage, wantStage)
					}
					if strings.HasSuffix(wantStage, "headers") && requests != 1 {
						t.Fatal("sent request after device provider failure")
					}
					if mode == "provider-error" && !errors.Is(err, providerErr) {
						t.Fatal("provider cause lost")
					}
					if mode == "cancel" && !errors.Is(err, context.Canceled) {
						t.Fatal("context cancellation lost")
					}
					if mode == "challenge" {
						var responseErr *GrandSlamResponseError
						if !errors.As(err, &responseErr) || responseErr.Response["Status"] == nil || responseErr.HTTPHeaders.Get("X-Test-Response") != "complete" {
							t.Fatal("server challenge lost")
						}
					}
				})
			}
		}
	}
}

func TestPasswordExchangePreflight(t *testing.T) {
	client, _ := New(Config{})
	calls := 0
	provider := func(context.Context, SRPStep) (http.Header, error) {
		calls++
		return nil, errors.New("secret provider data")
	}
	for _, options := range []PasswordExchangeOptions{{Locale: "en_US"}, {DeviceHeaders: provider}} {
		if result, err := client.ExchangePassword(context.Background(), "fixture@example.invalid", "password", options); err == nil || result != nil {
			t.Fatal("accepted missing configuration")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ExchangePassword(ctx, "fixture@example.invalid", "password", PasswordExchangeOptions{Locale: "en_US", DeviceHeaders: provider}); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancelled exchange was not stopped")
	}
	if calls != 0 {
		t.Fatal("called device provider during failed preflight")
	}
	if result, err := client.ExchangePassword(context.Background(), "fixture@example.invalid", "password", PasswordExchangeOptions{Locale: "en_US", DeviceHeaders: provider}); err == nil || result != nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("fresh-session exchange did not stop at provider failure")
	}
	if calls != 1 {
		t.Fatal("provider was not called exactly once")
	}
}

func TestContinuationKeyExchangePublicEntry(t *testing.T) {
	client, _ := New(Config{})
	calls := 0
	provider := func(context.Context, SRPStep) (http.Header, error) {
		calls++
		return nil, errors.New("secret provider data")
	}
	options := SRPExchangeOptions{Locale: "en_US", DeviceHeaders: provider}
	for _, input := range [][2]string{{"", "synthetic-ck"}, {"fixture@example.invalid", ""}} {
		if result, err := client.ExchangeContinuationKey(context.Background(), input[0], input[1], options); err == nil || result != nil {
			t.Fatal("accepted missing credential")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ExchangeContinuationKey(ctx, "fixture@example.invalid", "synthetic-ck", options); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancelled CK exchange was not stopped")
	}
	if calls != 0 {
		t.Fatal("called provider during failed CK preflight")
	}
	result, err := client.ExchangeContinuationKey(context.Background(), "fixture@example.invalid", "synthetic-ck", options)
	var exchangeErr *ExchangeError
	if result != nil || !errors.As(err, &exchangeErr) || exchangeErr.Stage != "init headers" || strings.Contains(err.Error(), "secret") || calls != 1 {
		t.Fatal("CK entry did not use the guarded SRP path")
	}
}

func TestPublicExchangeCredentialFlags(t *testing.T) {
	for _, ck := range []bool{false, true} {
		requests := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			var body struct {
				Request struct {
					CPD struct{ CKAuth, CKGen bool } `json:"cpd"`
				} `json:"Request"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Request.CPD.CKAuth != ck || body.Request.CPD.CKGen == ck {
				t.Error("public entry selected the wrong credential mode")
			}
			// Stop at init; the independent fixtures above cover the proof exchange.
			w.WriteHeader(http.StatusUnauthorized)
		}))
		client, _ := New(Config{HTTPClient: server.Client(), GrandSlamURL: server.URL})
		options := SRPExchangeOptions{Locale: "en_US", DeviceHeaders: func(context.Context, SRPStep) (http.Header, error) {
			return http.Header{"X-Test": {"synthetic"}}, nil
		}}
		exchange := client.ExchangePassword
		if ck {
			exchange = client.ExchangeContinuationKey
		}
		result, err := exchange(context.Background(), "fixture@example.invalid", "synthetic-credential", options)
		server.Close()
		var stage *ExchangeError
		if result != nil || !errors.As(err, &stage) || stage.Stage != "init" || requests != 1 {
			t.Fatal("exchange retried or accepted rejected init")
		}
	}
}
