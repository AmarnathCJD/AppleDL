package applemusic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
)

type LicenseRequest struct {
	Protocol, GUID, AssetID, KeyURI, SPC string
	Offline                              bool
}

// Body reproduces PlayerDrmNetworking.createKeyRequestBody. SPC is supplied by
// the native exchange; the Go implementation does not synthesize it.
func (r LicenseRequest) Body() ([]byte, error) {
	switch strings.ToLower(r.Protocol) {
	case "simplified":
		return json.Marshal(struct {
			GUID    string `json:"guid"`
			AdamID  string `json:"adamId"`
			Offline string `json:"offline"`
			KeyURI  string `json:"keyUri"`
			SPC     string `json:"spc"`
		}{r.GUID, r.AssetID, strconv.FormatBool(r.Offline), r.KeyURI, r.SPC})
	case "standard":
		type key struct {
			ID  string `json:"id"`
			URI string `json:"uri"`
			SPC string `json:"spc"`
		}
		type request struct {
			Keys []key `json:"streaming-keys"`
		}
		return json.Marshal(struct {
			Request request `json:"fairplay-streaming-request"`
		}{request{[]key{{"0", r.KeyURI, r.SPC}}}})
	default:
		return nil, errors.New("invalid license protocol")
	}
}

var (
	ErrLicenseSlot          = errors.New("license slot unavailable (-1004)")
	ErrLicenseSlotExhausted = errors.New("license slot unavailable after retry (-84)")
)

// LicenseEnvelope contains an opaque CKC, not a raw media decryption key.
// ExpiresAtMillis uses Android's Long.MAX_VALUE for an indefinite lease.
type LicenseEnvelope struct {
	CKC, Protocol                 string
	Version, Status               int32
	RenewAfter, ExpiresAtMillis   int64
	RequestedOffline, SentOffline bool
}

func (*LicenseEnvelope) String() string   { return "LicenseEnvelope{redacted}" }
func (*LicenseEnvelope) GoString() string { return "LicenseEnvelope{redacted}" }
func (r *LicenseEnvelope) Destroy() {
	if r != nil {
		*r = LicenseEnvelope{}
	}
}

func ParseLicenseResponse(protocol string, data []byte, nowMillis int64) (*LicenseEnvelope, error) {
	if len(data) > maxResponseBytes || requiredPlaybackFields(data) != nil {
		return nil, errors.New("invalid license response")
	}
	protocol = strings.ToLower(protocol)
	out := &LicenseEnvelope{Protocol: protocol, RenewAfter: -1, ExpiresAtMillis: math.MaxInt64}
	switch protocol {
	case "simplified":
		var wire struct {
			Version int32  `json:"version"`
			CKC     string `json:"ckc"`
			Renew   int64  `json:"renew-after"`
			Status  int32  `json:"status"`
		}
		wire.Renew = -1
		if nonnullPlaybackFields(data, "version", "ckc", "renew-after", "status") != nil || decodePlaybackObject(data, &wire) != nil {
			return nil, errors.New("invalid simplified license response")
		}
		if wire.Status == -1004 {
			return nil, ErrLicenseSlot
		}
		out.CKC, out.Version, out.Status, out.RenewAfter = wire.CKC, wire.Version, wire.Status, wire.Renew
		if wire.Renew != -1 {
			// Deliberate local validation: reject arithmetic overflow rather than
			// reproducing Java's wrapping timestamp for malformed responses.
			if wire.Renew > math.MaxInt64/1000 || wire.Renew < math.MinInt64/1000 {
				return nil, errors.New("license renewal overflow")
			}
			delta := wire.Renew * 1000
			if (delta > 0 && nowMillis > math.MaxInt64-delta) || (delta < 0 && nowMillis < math.MinInt64-delta) {
				return nil, errors.New("license expiry overflow")
			}
			out.ExpiresAtMillis = nowMillis + delta
		}
	case "standard":
		var wire struct {
			Response json.RawMessage `json:"fairplay-streaming-response"`
		}
		if decodePlaybackObject(data, &wire) != nil || requiredPlaybackFields(wire.Response) != nil {
			return nil, errors.New("invalid standard license response")
		}
		var response struct {
			Version int32             `json:"version"`
			Keys    []json.RawMessage `json:"streaming-keys"`
		}
		if nonnullPlaybackFields(wire.Response, "version", "streaming-keys") != nil || decodePlaybackObject(wire.Response, &response) != nil || len(response.Keys) == 0 {
			return nil, errors.New("standard license key missing or invalid")
		}
		for i, raw := range response.Keys {
			var key struct {
				ID     int32  `json:"id"`
				CKC    string `json:"ckc"`
				Status int32  `json:"status"`
				Event  string `json:"event"`
			}
			key.Status = -1
			if requiredPlaybackFields(raw) != nil || nonnullPlaybackFields(raw, "id", "ckc", "status", "event") != nil || decodePlaybackObject(raw, &key) != nil {
				return nil, errors.New("invalid standard license key")
			}
			if i == 0 {
				out.CKC, out.Status = key.CKC, key.Status
			}
		}
		out.Version = response.Version
	default:
		return nil, errors.New("invalid license protocol")
	}
	if out.CKC == "" {
		return nil, errors.New("license CKC missing")
	}
	return out, nil
}

func nonnullPlaybackFields(data []byte, names ...string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return errors.New("invalid playback object")
	}
	for _, name := range names {
		if bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return errors.New("unexpected null playback field")
		}
	}
	return nil
}

// LicenseExchange is supplied by the caller. It must handle endpoint validation,
// store cookies, device headers and bag-driven signing, and bound its response.
// Tests can supply fixture responses without any network activity.
type LicenseExchange func(context.Context, []byte) ([]byte, error)

// ExchangeLicense ports the single simplified-protocol slot retry. Metadata
// retains the original Offline value; only the second request body is toggled.
// No retry occurs for other errors or standard-protocol status values.
func ExchangeLicense(ctx context.Context, request LicenseRequest, nowMillis func() int64, exchange LicenseExchange) (*LicenseEnvelope, error) {
	if exchange == nil || nowMillis == nil {
		return nil, errors.New("license exchange and clock required")
	}
	sent := request
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		body, err := sent.Body()
		if err != nil {
			return nil, err
		}
		data, err := exchange(ctx, body)
		clear(body)
		if ctxErr := ctx.Err(); ctxErr != nil {
			clear(data)
			return nil, ctxErr
		}
		if err != nil {
			clear(data)
			var status *PlaybackHTTPError
			if errors.As(err, &status) {
				return nil, &PlaybackHTTPError{status.StatusCode}
			}
			if errors.Is(err, ErrMediaDeviceChallenge) {
				return nil, ErrMediaDeviceChallenge
			}
			return nil, errors.New("license exchange failed")
		}
		result, err := ParseLicenseResponse(sent.Protocol, data, nowMillis())
		clear(data)
		if errors.Is(err, ErrLicenseSlot) {
			if attempt == 1 {
				return nil, ErrLicenseSlotExhausted
			}
			sent.Offline = !request.Offline
			continue
		}
		if err != nil {
			return nil, err
		}
		result.RequestedOffline, result.SentOffline = request.Offline, sent.Offline
		return result, nil
	}
	return nil, ErrLicenseSlotExhausted
}
