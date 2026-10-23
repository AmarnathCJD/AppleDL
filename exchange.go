package applemusic

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// SRPStep identifies the request for which fresh device headers are needed.
type SRPStep string

const (
	SRPInit     SRPStep = "init"
	SRPComplete SRPStep = "complete"
)

// DeviceHeaderProvider obtains fresh headers from the caller's matching device
// environment. Calls are sequential, once before each request. This package
// does not generate or provision Anisette data. Do not log these headers.
type DeviceHeaderProvider func(context.Context, SRPStep) (http.Header, error)

// SRPExchangeOptions configures either password or continuation-key exchange.
type SRPExchangeOptions struct {
	Locale        string
	DeviceHeaders DeviceHeaderProvider
}

// PasswordExchangeOptions is retained for existing password callers.
type PasswordExchangeOptions = SRPExchangeOptions

// SRPExchangeResult is the decoded IdMS result after verifying the SRP
// server proof. AccountData, Response and HTTPHeaders can contain sensitive tokens.
// This is not a completed Apple Music login: interactive verification, PET
// commerce authentication, account persistence and media tokens are separate.
// NP is preserved without interpreting its currently unresolved semantics.
type SRPExchangeResult struct {
	AccountData map[string]json.RawMessage
	// Response preserves the complete envelope, including any Status/challenge.
	// A verified proof and decrypted SPD do not establish challenge completion.
	Response      map[string]json.RawMessage
	TransactionID string
	NP            []byte
	HTTPHeaders   http.Header
}

func (*SRPExchangeResult) String() string   { return "SRPExchangeResult{redacted}" }
func (*SRPExchangeResult) GoString() string { return "SRPExchangeResult{redacted}" }

// Destroy performs best-effort cleanup. Go strings and copies held by callers
// cannot be guaranteed erased. The result must not be used concurrently.
func (r *SRPExchangeResult) Destroy() {
	if r == nil {
		return
	}
	for _, fields := range []map[string]json.RawMessage{r.AccountData, r.Response} {
		for k, raw := range fields {
			clear(raw)
			delete(fields, k)
		}
	}
	for k, values := range r.HTTPHeaders {
		clear(values)
		delete(r.HTTPHeaders, k)
	}
	clear(r.NP)
	*r = SRPExchangeResult{}
}

// PasswordExchangeResult is retained for existing password callers.
type PasswordExchangeResult = SRPExchangeResult

// ExchangeError reports the failed stage without including credentials, server
// payloads or device-provider diagnostics. Unwrap supports errors.Is/errors.As;
// inspect the cause explicitly only when needed, as it may contain secrets.
type ExchangeError struct {
	Stage string
	Err   error
}

func (e *ExchangeError) Error() string { return "SRP exchange failed at " + e.Stage }
func (e *ExchangeError) Unwrap() error { return e.Err }

// ExchangePassword runs one native password SRP exchange. It uses fresh random
// client state, ckauth=false and ckgen=true. It verifies M2 before decrypting SPD
// and returns no account data on any failure. Device data must be supplied by
// the caller. Server challenges are exposed through GrandSlamResponseError;
// this method does not retry or complete interactive verification automatically.
func (c *Client) ExchangePassword(ctx context.Context, username, password string, options PasswordExchangeOptions) (*PasswordExchangeResult, error) {
	return c.beginExchange(ctx, username, password, options, false)
}

// ExchangeContinuationKey runs the native CKToken SRP route using a continuation
// key already obtained by the caller for this account. It uses ckauth=true and
// ckgen=false; the credential otherwise follows the same SRP proof path. It does
// not read app accounts, refresh or persist keys, or fall back to interactive
// sign-in. Live acceptance of this route remains unverified.
func (c *Client) ExchangeContinuationKey(ctx context.Context, username, continuationKey string, options SRPExchangeOptions) (*SRPExchangeResult, error) {
	return c.beginExchange(ctx, username, continuationKey, options, true)
}

func (c *Client) beginExchange(ctx context.Context, username, credential string, options SRPExchangeOptions, ckAuth bool) (*SRPExchangeResult, error) {
	if username == "" || credential == "" || options.Locale == "" || options.DeviceHeaders == nil {
		return nil, errors.New("SRP exchange requires username, credential, locale and a device header provider")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	session, err := NewSRPSession(username)
	if err != nil {
		return nil, err
	}
	return c.exchangeCredential(ctx, username, credential, options, session, ckAuth)
}

func (c *Client) exchangeCredential(ctx context.Context, username, credential string, options SRPExchangeOptions, session *SRPSession, ckAuth bool) (*SRPExchangeResult, error) {
	defer session.Destroy()
	fail := func(stage string, err error) (*PasswordExchangeResult, error) {
		return nil, &ExchangeError{Stage: stage, Err: err}
	}
	headersFor := func(step SRPStep) (http.Header, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		headers, err := options.DeviceHeaders(ctx, step)
		if err != nil {
			return nil, err
		}
		if len(headers) == 0 {
			return nil, errors.New("device header provider returned no headers")
		}
		return headers.Clone(), nil
	}
	headers, err := headersFor(SRPInit)
	if err != nil {
		return fail("init headers", err)
	}
	wireOptions := GrandSlamOptions{Locale: options.Locale, CKAuth: ckAuth, CKGen: !ckAuth, Headers: headers}
	initial, err := c.InitSRP(ctx, username, session.PublicKey(), wireOptions)
	if err != nil {
		return fail("init", err)
	}
	proof, err := session.Respond(credential, initial.Challenge)
	if err != nil {
		return fail("client proof", err)
	}
	defer clear(proof)
	headers, err = headersFor(SRPComplete)
	if err != nil {
		return fail("complete headers", err)
	}
	wireOptions.Headers = headers
	complete, err := c.CompleteSRP(ctx, username, initial.Continuation, proof, wireOptions)
	if err != nil {
		return fail("complete", err)
	}
	key, err := session.VerifyServerProof(complete.ServerProof)
	if err != nil {
		return fail("server proof", err)
	}
	defer clear(key)
	account, err := DecryptSPD(key, complete.SPD)
	if err != nil {
		return fail("account data", err)
	}
	return &PasswordExchangeResult{
		AccountData: account, Response: complete.Response, TransactionID: initial.TransactionID,
		NP: complete.NP, HTTPHeaders: complete.HTTPHeaders,
	}, nil
}
