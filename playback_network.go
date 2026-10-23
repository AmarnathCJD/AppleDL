package applemusic

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"time"
)

// BagConfig and PlaybackStoreConfigurationImpl use enhanced-audio/hls-key-server-url,
// not the unrelated fps-request bag entry. The supplied APK selects simplified.
const PlaybackLicenseURL = "https://play.itunes.apple.com/WebObjects/MZPlay.woa/music/fps"
const PlaybackCertificateURL = "https://s.mzstatic.com/skdtool_2021_certbundle.bin"

// The reviewed POST has V1.5 anisette, with no matching FPDI, Mescal or external
// integrity rule. Pin all policy inputs until a general matcher is implemented.
//
//go:embed playback_policy.json
var reviewedPlaybackPolicy []byte

type PlaybackProfile struct{ reviewed bool }

func ParsePlaybackProfile(raw []byte) (*PlaybackProfile, error) {
	if _, err := ParseCommerceProfile(raw); err != nil {
		return nil, err
	}
	var bag, want map[string]any
	if json.Unmarshal(raw, &bag) != nil || json.Unmarshal(reviewedPlaybackPolicy, &want) != nil {
		return nil, errors.New("invalid playback bag")
	}
	common, _ := bag["musicCommon"].(map[string]any)
	for key, value := range want {
		got := bag[key]
		if key == "musicMescal" {
			got = common[key]
		}
		if !reflect.DeepEqual(got, value) {
			return nil, errors.New("unsupported playback policy; decorator rules need review")
		}
	}
	audio, _ := bag["enhanced-audio"].(map[string]any)
	if audio["hls-key-server-url"] != PlaybackLicenseURL || bag["fps-cert"] != PlaybackCertificateURL {
		return nil, errors.New("unsupported enhanced playback endpoint")
	}
	return &PlaybackProfile{true}, nil
}

func (c *Client) FetchPlaybackProfile(ctx context.Context, userAgent string) (*PlaybackProfile, error) {
	if userAgent == "" || !validMetadataText(userAgent) {
		return nil, errors.New("invalid playback user agent")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, CommerceBagURL, nil)
	if err != nil {
		return nil, errors.New("create playback bag request failed")
	}
	req.Header.Set("User-Agent", userAgent)
	isolate := *c
	isolate.http = newMediaHTTP(c.http)
	raw, _, err := isolate.send(req)
	if err != nil {
		return nil, err
	}
	return ParsePlaybackProfile(raw)
}

// PlaybackSession owns a separate view of the saved account and URL-scoped
// commerce cookies. X-Token prefers xToken, falling back to passwordToken, as in
// p441vb.C6427a; it is not the catalog bearer token.
type PlaybackSession struct {
	account *MediaTokenSession
	token   string
}

func (*PlaybackSession) String() string   { return "PlaybackSession{redacted}" }
func (*PlaybackSession) GoString() string { return "PlaybackSession{redacted}" }
func (s *PlaybackSession) Destroy() {
	if s != nil {
		if s.account != nil {
			s.account.Destroy()
		}
		*s = PlaybackSession{}
	}
}
func NewPlaybackSession(r *CommerceResponse, obtainedAt time.Time) (*PlaybackSession, error) {
	if r == nil {
		return nil, errors.New("playback account required")
	}
	s, err := NewMediaTokenSession(r, obtainedAt)
	if err != nil {
		return nil, err
	}
	token, ok := r.Fields["xToken"].(string)
	if !ok {
		token, _ = r.Fields["passwordToken"].(string)
	}
	dsid, err := strconv.ParseInt(s.dsid, 10, 64)
	if err != nil || dsid <= 0 || !validMediaBearerToken(token) {
		s.Destroy()
		return nil, errors.New("playback account token or identifier missing or invalid")
	}
	return &PlaybackSession{s, token}, nil
}

type PlaybackRequestPreparer func(context.Context, PlaybackRequestPlan) (http.Header, error)

type PlaybackHTTPError struct{ StatusCode int }

func (e *PlaybackHTTPError) Error() string {
	return fmt.Sprintf("playback license HTTP status %d", e.StatusCode)
}

// FetchPlaybackLicense performs the APK's simplified exchange, including its
// one -1004 retry. Each POST gets fresh V1.5 headers. Redirects and implicit
// cookies are disabled, and no signed material is included in errors.
func (c *Client) FetchPlaybackLicense(ctx context.Context, p *PlaybackProfile, s *PlaybackSession, m DeviceMetadata, request LicenseRequest, prepare PlaybackRequestPreparer) (*LicenseEnvelope, error) {
	if p == nil || !p.reviewed || s == nil || s.account == nil || s.token == "" || prepare == nil {
		return nil, errors.New("playback profile, account and preparer required")
	}
	if request.Protocol != "simplified" || request.GUID != m.StableID || m.StableID == "" || m.UserAgent == "" || m.Language == "" || request.AssetID == "" {
		return nil, errors.New("invalid playback request identity or protocol")
	}
	if _, err := strconv.ParseUint(request.AssetID, 10, 64); err != nil {
		return nil, errors.New("invalid playback asset identifier")
	}
	if len(request.SPC) > maxResponseBytes || request.SPC == "" {
		return nil, errors.New("invalid playback SPC size")
	}
	spc, err := base64.StdEncoding.Strict().DecodeString(request.SPC)
	clear(spc)
	if err != nil {
		return nil, errors.New("invalid playback SPC encoding")
	}
	dsid, _ := strconv.ParseInt(s.account.dsid, 10, 64)
	hc := newMediaHTTP(c.http)
	return ExchangeLicense(ctx, request, func() int64 { return time.Now().UnixMilli() }, func(ctx context.Context, body []byte) ([]byte, error) {
		cookies, err := s.account.cookieHeaderFor(time.Now(), PlaybackLicenseURL)
		if err != nil {
			return nil, err
		}
		plan, err := PlanLicenseRequest(PlaybackLicenseURL, StoreHeaderValues{UserAgent: m.UserAgent, Locale: m.Language, Storefront: s.account.storefront + " t:music31", Cookie: cookies, XToken: s.token, DSID: dsid}, 0, request)
		if err != nil {
			return nil, err
		}
		clear(plan.Body)
		plan.Body = bytes.Clone(body) // preserves the retry's offline toggle
		defer clear(plan.Body)
		original := plan.Headers.Clone()
		prepared, err := prepare(ctx, *plan)
		if err != nil {
			return nil, err
		}
		for key, values := range original {
			if !reflect.DeepEqual(prepared.Values(key), values) {
				return nil, errors.New("playback preparer changed account headers")
			}
		}
		for key, values := range prepared {
			if key != http.CanonicalHeaderKey(key) {
				return nil, errors.New("noncanonical playback header")
			}
			if _, ok := original[key]; ok {
				continue
			}
			if (key != "X-Apple-Amd" && key != "X-Apple-Amd-M") || len(values) != 1 || values[0] == "" || !validMetadataText(values[0]) {
				return nil, errors.New("unsupported playback prepared header")
			}
		}
		if prepared.Get("X-Apple-AMD") == "" || prepared.Get("X-Apple-AMD-M") == "" {
			return nil, errors.New("playback V1.5 headers missing")
		}
		// Send the original body: a preparer cannot mutate the signed payload.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, PlaybackLicenseURL, bytes.NewReader(body))
		if err != nil {
			return nil, errors.New("create playback license request failed")
		}
		req.Header = prepared.Clone()
		resp, err := hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("playback license transport failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, &PlaybackHTTPError{resp.StatusCode}
		}
		if resp.Header.Get("X-Apple-AMD-Action") != "" || resp.Header.Get("X-Apple-AMD-Data") != "" {
			return nil, ErrMediaDeviceChallenge
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		if err != nil || len(raw) > maxResponseBytes {
			clear(raw)
			return nil, errors.New("invalid playback license response size or read")
		}
		return raw, nil
	})
}
