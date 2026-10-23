package applemusic

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
)

const MediaTokenURL = "https://sf-api-token-service.itunes.apple.com/apiToken"
const mediaTokenRequestURL = MediaTokenURL + "?clientClass=apple&clientId=musicAndroid&version=1"

// MediaTokenProfile supports only the bag policy reviewed against build 1606.
type MediaTokenProfile struct{ commerce *CommerceProfile }

func ParseMediaTokenProfile(raw []byte) (*MediaTokenProfile, error) {
	p, err := ParseCommerceProfile(raw)
	if err != nil {
		return nil, err
	}
	var bag map[string]any
	if json.Unmarshal(raw, &bag) != nil || bag["sf-api-token-service-url"] != MediaTokenURL {
		return nil, errors.New("unsupported media-token bag endpoint")
	}
	return &MediaTokenProfile{commerce: p}, nil
}

func (c *Client) FetchMediaTokenProfile(ctx context.Context, userAgent string) (*MediaTokenProfile, error) {
	if userAgent == "" || !validMetadataText(userAgent) {
		return nil, errors.New("invalid media-token user agent")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, CommerceBagURL, nil)
	if err != nil {
		return nil, errors.New("create media-token bag request failed")
	}
	req.Header.Set("User-Agent", userAgent)
	// Neither client-wide auth headers nor its cookie jar belong on the bag.
	isolate := *c
	isolate.http = newMediaHTTP(c.http)
	raw, _, err := isolate.send(req)
	if err != nil {
		return nil, err
	}
	return ParseMediaTokenProfile(raw)
}

var mediaAccountStorefront = regexp.MustCompile(`^[0-9]{6}(?:-[0-9]{1,6},[0-9]{1,6})?$`)

// MediaTokenSession is a narrow installation of a standalone commerce response.
// It requires X-Set-Apple-Store-Front; the native local-account fallback, custom
// X-Apple-Set-* cookie headers and ambiguous same-name cookies are unsupported.
// Body cookies are not synthesized. No Android or iCloud account is imported.
type MediaTokenSession struct {
	storefront, dsid, altDSID string
	cookies                   []*http.Cookie
	obtainedAt                time.Time
}

func (*MediaTokenSession) String() string   { return "MediaTokenSession{redacted}" }
func (*MediaTokenSession) GoString() string { return "MediaTokenSession{redacted}" }
func (s *MediaTokenSession) Destroy() {
	if s != nil {
		clear(s.cookies)
		*s = MediaTokenSession{}
	}
}

func NewMediaTokenSession(r *CommerceResponse, obtainedAt time.Time) (*MediaTokenSession, error) {
	if r.Observation() != CommerceCredentialReceived || obtainedAt.IsZero() {
		return nil, errors.New("media-token session requires a saved commerce credential")
	}
	a, err := r.ExtractAccount()
	if err != nil {
		return nil, err
	}
	sf := r.HTTPHeaders.Values("X-Set-Apple-Store-Front")
	if len(sf) != 1 || !mediaAccountStorefront.MatchString(sf[0]) {
		return nil, errors.New("media-token account storefront is missing or unsupported")
	}
	for _, key := range []string{"X-Apple-Set-User-Cookie", "X-Apple-Set-Cookie"} {
		if len(r.HTTPHeaders.Values(key)) != 0 {
			return nil, errors.New("custom commerce cookie installation is not implemented")
		}
	}
	return &MediaTokenSession{sf[0], strconv.FormatUint(a.DSID, 10), a.AltDSID,
		(&http.Response{Header: r.HTTPHeaders}).Cookies(), obtainedAt}, nil
}

// cookieHeader replays Set-Cookie at its original receipt time. A Max-Age must
// never gain a new lifetime just because the encrypted snapshot was reopened.
func (s *MediaTokenSession) cookieHeader(now time.Time) (string, error) {
	return s.cookieHeaderFor(now, MediaTokenURL)
}

func (s *MediaTokenSession) cookieHeaderFor(now time.Time, endpoint string) (string, error) {
	if now.Before(s.obtainedAt) {
		return "", errors.New("commerce cookie receipt time is in the future")
	}
	jar, _ := cookiejar.New(nil)
	origin, _ := url.Parse(CommerceAuthURL)
	target, err := url.Parse(endpoint)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil {
		return "", errors.New("invalid commerce cookie target")
	}
	for _, saved := range s.cookies {
		c := *saved
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		// The origin is fixed. Avoid accepting a public-suffix cookie without
		// adding a new public-suffix-list dependency to this narrow client.
		if domain != "" && domain != "auth.itunes.apple.com" && domain != "itunes.apple.com" && domain != "apple.com" {
			continue
		}
		if c.MaxAge > 0 {
			if int64(c.MaxAge) > int64((1<<63-1)/time.Second) {
				return "", errors.New("commerce cookie lifetime exceeds bounds")
			}
			c.Expires = s.obtainedAt.Add(time.Duration(c.MaxAge) * time.Second)
			c.MaxAge = 0
		}
		if c.MaxAge < 0 || (!c.Expires.IsZero() && !now.Before(c.Expires)) {
			c.MaxAge = -1 // preserve deletion order for the same domain/name/path
		}
		jar.SetCookies(origin, []*http.Cookie{&c})
	}
	req := &http.Request{Header: make(http.Header)}
	seen := make(map[string]bool)
	for _, c := range jar.Cookies(target) {
		if seen[c.Name] {
			return "", errors.New("ambiguous same-name commerce cookies require native precedence mapping")
		}
		seen[c.Name] = true
		req.AddCookie(c)
	}
	return req.Header.Get("Cookie"), nil
}

type MediaTokenRequest struct {
	URL, Method string
	Headers     http.Header
}

func (MediaTokenRequest) String() string   { return "MediaTokenRequest{redacted}" }
func (MediaTokenRequest) GoString() string { return "MediaTokenRequest{redacted}" }

type MediaTokenRequestPreparer func(context.Context, MediaTokenRequest) (http.Header, error)

// MediaTokenSigningData implements the reviewed signed-actions apiToken rule.
// Values are concatenated with no names or separators, followed by clientId.
// The current port requires the signed headers rather than silently omitting
// identity information when standalone provisioning is incomplete.
func MediaTokenSigningData(req MediaTokenRequest) ([]byte, error) {
	if req.URL != mediaTokenRequestURL || req.Method != http.MethodGet {
		return nil, errors.New("unsupported media-token signing destination or method")
	}
	var data []byte
	for _, key := range []string{"X-Apple-Store-Front", "X-Apple-Client-Application", "X-Request-Timestamp", "X-Apple-AMD-M", "X-DSID"} {
		values := req.Headers.Values(key)
		if len(values) != 1 || values[0] == "" || !validMetadataText(values[0]) {
			clear(data)
			return nil, errors.New("media-token signed header missing or invalid")
		}
		data = append(data, values[0]...)
	}
	if req.Headers.Get("X-Apple-Client-Application") != "musicAndroid" {
		clear(data)
		return nil, errors.New("unsupported media-token client identifier")
	}
	stamp := req.Headers.Get("X-Request-Timestamp")
	parsed, err := time.Parse("2006-01-02T15:04:05Z", stamp)
	dsid, dsidErr := strconv.ParseUint(req.Headers.Get("X-DSID"), 10, 64)
	if err != nil || parsed.Format("2006-01-02T15:04:05Z") != stamp || dsidErr != nil || dsid == 0 {
		clear(data)
		return nil, errors.New("invalid media-token timestamp or account identifier")
	}
	return append(data, "musicAndroid"...), nil
}

// A bearer token is opaque ASCII without whitespace or control characters.
// Keep its size bound separate from the smaller device-metadata field bound.
func validMediaBearerToken(token string) bool {
	if len(token) == 0 || len(token) > 65536 {
		return false
	}
	for i := range len(token) {
		if token[i] < 0x21 || token[i] > 0x7e {
			return false
		}
	}
	return true
}

type MediaTokenResponse struct {
	Token      string
	ObtainedAt time.Time
}

func (*MediaTokenResponse) String() string   { return "MediaTokenResponse{redacted}" }
func (*MediaTokenResponse) GoString() string { return "MediaTokenResponse{redacted}" }
func (r *MediaTokenResponse) Destroy() {
	if r != nil {
		*r = MediaTokenResponse{}
	}
}

// FetchMediaToken performs one signed GET. No redirects, password attempts,
// provisioning retries or implicit cookies are added. Issuance is separate from
// media API acceptance, subscription entitlement and playback authorization.
func (c *Client) FetchMediaToken(ctx context.Context, p *MediaTokenProfile, s *MediaTokenSession, m DeviceMetadata, prepare MediaTokenRequestPreparer) (*MediaTokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == nil || p.commerce == nil || s == nil || s.dsid == "" || s.altDSID == "" || !validMetadataText(s.altDSID) || prepare == nil {
		return nil, errors.New("media-token profile, session and preparer required")
	}
	h, err := p.commerce.Headers(m)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	h.Set("X-Apple-Store-Front", s.storefront+" t:music31")
	h.Set("X-Apple-Client-Application", "musicAndroid")
	h.Set("X-Request-Timestamp", now.Format("2006-01-02T15:04:05Z"))
	h.Set("X-DSID", s.dsid)
	h.Set("X-Apple-ADSID", s.altDSID)
	cookies, err := s.cookieHeader(now)
	if err != nil {
		return nil, err
	}
	if cookies != "" {
		h.Set("Cookie", cookies)
	}
	prepared, err := prepare(ctx, MediaTokenRequest{mediaTokenRequestURL, http.MethodGet, h.Clone()})
	if err != nil {
		return nil, err
	}
	// Keep signed/account headers immutable across the native preparer.
	for key, values := range h {
		got := prepared.Values(key)
		if len(got) != 1 || got[0] != values[0] {
			return nil, errors.New("media-token preparer changed request headers")
		}
	}
	for key, values := range prepared {
		if key != http.CanonicalHeaderKey(key) {
			return nil, errors.New("media-token preparer returned noncanonical headers")
		}
		if _, ok := h[http.CanonicalHeaderKey(key)]; ok {
			continue
		}
		if key != "X-Apple-Amd" && key != "X-Apple-Amd-M" && key != "X-Apple-Actionsignature" {
			return nil, errors.New("unsupported media-token prepared header")
		}
		if len(values) != 1 || values[0] == "" || !validMetadataText(values[0]) {
			return nil, errors.New("invalid media-token prepared header")
		}
	}
	for _, key := range []string{"X-Apple-AMD", "X-Apple-AMD-M", "X-Apple-ActionSignature"} {
		if prepared.Get(key) == "" {
			return nil, errors.New("media-token device signature missing")
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mediaTokenRequestURL, nil)
	if err != nil {
		return nil, errors.New("create media-token request failed")
	}
	req.Header = prepared.Clone()
	isolate := *c
	isolate.http = newMediaHTTP(c.http)
	raw, responseHeaders, err := isolate.send(req)
	defer clear(raw)
	if responseHeaders.Get("X-Apple-AMD-Action") != "" || responseHeaders.Get("X-Apple-AMD-Data") != "" {
		return nil, ErrMediaDeviceChallenge
	}
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		if _, err := plist.Unmarshal(raw, &fields); err != nil {
			return nil, errors.New("invalid media-token response dictionary")
		}
	}
	token, ok := fields["token"].(string)
	if !ok || !validMediaBearerToken(token) {
		return nil, errors.New("media-token response has no usable token")
	}
	return &MediaTokenResponse{token, time.Now().UTC()}, nil
}
