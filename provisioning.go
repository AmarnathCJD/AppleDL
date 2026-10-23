package applemusic

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"howett.net/plist"
)

// ProvisioningStep identifies which bag endpoint needs fresh device headers.
type ProvisioningStep string

const (
	ProvisioningStart  ProvisioningStep = "midStartProvisioning"
	ProvisioningFinish ProvisioningStep = "midFinishProvisioning"
	AnisetteV3DSID     int64            = -2
	AnisetteV15DSID    int64            = -1
)

// ProvisioningResponseError preserves an unusable plist envelope and its HTTP
// headers, including server challenges. Error redacts this sensitive data.
// Server status codes are not yet mapped to retry or account-verification steps.
type ProvisioningResponseError struct {
	Step        ProvisioningStep
	Envelope    map[string]any
	HTTPHeaders http.Header
}

func (*ProvisioningResponseError) Error() string {
	return "provisioning response does not contain a usable result"
}

type ProvisioningStartResponse struct {
	SPIM        []byte
	Envelope    map[string]any
	HTTPHeaders http.Header
}

type ProvisioningFinishResponse struct {
	PTM         []byte
	TK          []byte
	Envelope    map[string]any
	HTTPHeaders http.Header
}

// StartProvisioning sends the observed empty plist Request/Header envelope to
// the trusted midStartProvisioning URL resolved by the caller from Apple's bag.
// Headers must belong to the matching device environment. No ADI state changes
// happen in this method; its SPIM must next be passed to the native provider.
func (c *Client) StartProvisioning(ctx context.Context, endpoint string, headers http.Header) (*ProvisioningStartResponse, error) {
	envelope, responseHeaders, err := c.provisioningRequest(ctx, endpoint, map[string]any{}, headers)
	if err != nil {
		return nil, err
	}
	response, _ := envelope["Response"].(map[string]any)
	spim, ok := provisioningBytes(response, "spim")
	if !ok {
		return nil, &ProvisioningResponseError{ProvisioningStart, envelope, responseHeaders}
	}
	return &ProvisioningStartResponse{spim, envelope, responseHeaders}, nil
}

// FinishProvisioning sends CPIM as a Base64 STRING inside the plist Request.
// PTM and TK are returned as decoded bytes, ready for the same native session's
// Finish call. A successful HTTP exchange alone does not provision that session.
func (c *Client) FinishProvisioning(ctx context.Context, endpoint string, cpim []byte, headers http.Header) (*ProvisioningFinishResponse, error) {
	if len(cpim) == 0 || len(cpim) > maxResponseBytes {
		return nil, errors.New("provisioning requires nonempty CPIM within the 4 MiB local limit")
	}
	envelope, responseHeaders, err := c.provisioningRequest(ctx, endpoint,
		map[string]any{"cpim": base64.StdEncoding.EncodeToString(cpim)}, headers)
	if err != nil {
		return nil, err
	}
	response, _ := envelope["Response"].(map[string]any)
	ptm, okP := provisioningBytes(response, "ptm")
	tk, okT := provisioningBytes(response, "tk")
	if !okP || !okT {
		clear(ptm)
		clear(tk)
		return nil, &ProvisioningResponseError{ProvisioningFinish, envelope, responseHeaders}
	}
	return &ProvisioningFinishResponse{ptm, tk, envelope, responseHeaders}, nil
}

func provisioningBytes(response map[string]any, key string) ([]byte, bool) {
	value, ok := response[key].(string)
	if !ok || value == "" {
		return nil, false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}

func (c *Client) provisioningRequest(ctx context.Context, endpoint string, body map[string]any, headers http.Header) (map[string]any, http.Header, error) {
	data, err := plist.Marshal(map[string]any{"Header": map[string]any{}, "Request": body}, plist.XMLFormat)
	if err != nil {
		return nil, nil, errors.New("encode provisioning plist failed")
	}
	req, err := c.newPostRequest(ctx, endpoint, data, commerceContentType, headers)
	if err != nil {
		return nil, nil, err
	}
	// Sessions are stateful. Do not allow net/http to replay a POST even if a
	// caller supplied an idempotency header. Custom transports remain external.
	req.GetBody = nil
	data, responseHeaders, err := c.send(req)
	if err != nil {
		return nil, responseHeaders, err
	}
	var envelope map[string]any
	if _, err := plist.Unmarshal(data, &envelope); err != nil || envelope == nil {
		return nil, responseHeaders, errors.New("invalid provisioning plist dictionary")
	}
	return envelope, responseHeaders, nil
}

// NativeProvisioningSession owns one actual ADI session. Finish receives PTM
// followed by TK, as raw bytes. Close releases the temporary session, including
// after Finish, without erasing persisted provisioning. Close must not depend
// on a live request context and must return promptly. Implementations must not
// retain input byte slices. This package does not implement Apple's native ADI.
type NativeProvisioningSession interface {
	Finish(ctx context.Context, ptm, tk []byte) error
	Close() error
}

// NativeProvisioningStarter calls ADI with the chosen DSID and raw SPIM. It
// transfers ownership of CPIM and session to the caller. A nonnil session is
// closed even if an error is also returned. On failure before returning a
// session, the provider must release any native resources itself. Do not retain
// SPIM. Serialize calls if the underlying bridge supports only one session.
type NativeProvisioningStarter func(ctx context.Context, dsid int64, spim []byte) (cpim []byte, session NativeProvisioningSession, err error)

type ProvisioningOptions struct {
	StartURL  string // trusted bag midStartProvisioning URL
	FinishURL string // trusted bag midFinishProvisioning URL
	DSID      int64  // explicitly choose the account; V3 uses AnisetteV3DSID
	Headers   func(context.Context, ProvisioningStep) (http.Header, error)
	Native    NativeProvisioningStarter
}

// ProvisioningError identifies a failed stage without printing native errors or
// server data. Its unwrapped cause may be sensitive; inspect it explicitly.
type ProvisioningError struct {
	Stage string
	Err   error
}

func (e *ProvisioningError) Error() string { return "device provisioning failed at " + e.Stage }
func (e *ProvisioningError) Unwrap() error { return e.Err }

// ProvisionDevice runs the two network requests around a caller's actual native
// ADI session. It performs no automatic retry, erasure or account login. A nil
// result means the provider accepted Finish and released the session; validation
// of subsequent OTP requests remains separate. A cleanup error can be returned
// after native Finish succeeded, so callers must not blindly retry on any error.
func (c *Client) ProvisionDevice(ctx context.Context, options ProvisioningOptions) (err error) {
	if options.Native == nil || options.Headers == nil {
		return errors.New("device provisioning requires native and header providers")
	}
	for _, endpoint := range []string{options.StartURL, options.FinishURL} {
		if err := validateEndpoint(endpoint); err != nil {
			return err
		}
	}
	fail := func(stage string, cause error) error { return &ProvisioningError{stage, cause} }
	headersFor := func(step ProvisioningStep) (http.Header, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		headers, err := options.Headers(ctx, step)
		if err != nil {
			return nil, err
		}
		if len(headers) == 0 {
			return nil, errors.New("provisioning header provider returned no headers")
		}
		return headers.Clone(), nil
	}
	headers, err := headersFor(ProvisioningStart)
	if err != nil {
		return fail("start headers", err)
	}
	start, err := c.StartProvisioning(ctx, options.StartURL, headers)
	if err != nil {
		return fail("start request", err)
	}
	defer clear(start.SPIM)
	if err := ctx.Err(); err != nil {
		return fail("native start", err)
	}
	cpim, session, err := options.Native(ctx, options.DSID, start.SPIM)
	defer clear(cpim)
	if session != nil {
		defer func() {
			if closeErr := session.Close(); closeErr != nil {
				err = errors.Join(err, fail("native close", closeErr))
			}
		}()
	}
	if err != nil {
		return fail("native start", err)
	}
	if session == nil || len(cpim) == 0 || len(cpim) > maxResponseBytes {
		return fail("native start", errors.New("native provider returned no usable session or CPIM"))
	}
	headers, err = headersFor(ProvisioningFinish)
	if err != nil {
		return fail("finish headers", err)
	}
	finish, err := c.FinishProvisioning(ctx, options.FinishURL, cpim, headers)
	if err != nil {
		return fail("finish request", err)
	}
	defer clear(finish.PTM)
	defer clear(finish.TK)
	if err := ctx.Err(); err != nil {
		return fail("native finish", err)
	}
	if err := session.Finish(ctx, finish.PTM, finish.TK); err != nil {
		return fail("native finish", err)
	}
	return nil
}
