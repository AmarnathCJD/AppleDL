package applemusic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MediaConfig configures the AMP API observed in Android 7.0.0-beta (1606).
// BearerToken is a media API token, NOT the commerce passwordToken or IdMS PET.
// Supplying a token does not establish subscription entitlement.
type MediaConfig struct {
	HTTPClient  *http.Client
	BearerToken string
	DSID        string
	UserAgent   string
	Storefront  string // catalog country code, e.g. us; NOT numeric storeFrontId
	Language    string
}

type MediaClient struct {
	http       *http.Client
	headers    http.Header
	storefront string
	language   string
}

const (
	mediaCatalogHost = "amp-api.music.apple.com"
	mediaSearchHost  = "amp-api-edge.music.apple.com"
)

var ErrMediaTokenRequired = errors.New("media API bearer token required")

// ErrMediaDeviceChallenge reports the paired AMD response headers observed in
// Android's media interceptor. This client does not generate a response or retry.
var ErrMediaDeviceChallenge = errors.New("media device-auth challenge received; challenge response is not implemented")

func countryCode(s string) bool {
	return len(s) == 2 && s[0] >= 'a' && s[0] <= 'z' && s[1] >= 'a' && s[1] <= 'z'
}

// newMediaHTTP deliberately drops the caller's cookie jar. Public catalog and
// CDN requests must not inherit commerce cookies. Custom transports are trusted.
func newMediaHTTP(input *http.Client) *http.Client {
	c := http.Client{Timeout: 30 * time.Second}
	if input != nil {
		c = *input
	}
	c.Jar = nil
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func NewMedia(config MediaConfig) (*MediaClient, error) {
	if config.BearerToken == "" {
		return nil, ErrMediaTokenRequired
	}
	if !validMediaBearerToken(config.BearerToken) {
		return nil, errors.New("invalid media token")
	}
	if !countryCode(config.Storefront) {
		return nil, errors.New("storefront must be a lowercase two-letter country code")
	}
	if config.DSID != "" {
		n, err := strconv.ParseUint(config.DSID, 10, 64)
		if err != nil || n == 0 {
			return nil, errors.New("invalid media account identifier")
		}
	}
	if strings.ContainsAny(config.UserAgent, "\r\n") {
		return nil, errors.New("invalid media user agent")
	}
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+config.BearerToken)
	if config.DSID != "" {
		h.Set("X-Dsid", config.DSID)
	}
	if config.UserAgent != "" {
		h.Set("User-Agent", config.UserAgent)
	}
	hc := config.HTTPClient
	if hc == nil {
		var err error
		hc, err = defaultHTTPClient()
		if err != nil {
			return nil, err
		}
	}
	return &MediaClient{newMediaHTTP(hc), h, config.Storefront, config.Language}, nil
}

// MediaHTTPError omits URLs, signed query strings, tokens and response bodies.
type MediaHTTPError struct{ StatusCode int }

func (e *MediaHTTPError) Error() string { return fmt.Sprintf("media HTTP status %d", e.StatusCode) }

// MediaAPIError preserves only the number of API errors. Payloads can include
// account-specific details and should not enter ordinary CLI logs.
type MediaAPIError struct{ Count int }

func (e *MediaAPIError) Error() string { return fmt.Sprintf("media API returned %d error(s)", e.Count) }

func mediaJSON(ctx context.Context, hc *http.Client, endpoint string, headers http.Header, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("invalid media request")
	}
	if headers != nil {
		req.Header = headers.Clone()
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("media transport failed")
	}
	defer resp.Body.Close()
	if len(resp.Header.Values("X-Apple-AMD-Action")) > 0 && len(resp.Header.Values("X-Apple-AMD-Data")) > 0 {
		return ErrMediaDeviceChallenge
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &MediaHTTPError{resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return errors.New("read media response failed")
	}
	if len(data) > maxResponseBytes {
		return errors.New("media response exceeds size limit")
	}
	var envelope struct {
		Errors []json.RawMessage `json:"errors"`
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' || json.Unmarshal(data, &envelope) != nil {
		return errors.New("invalid media JSON response")
	}
	if len(envelope.Errors) > 0 {
		return &MediaAPIError{len(envelope.Errors)}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("invalid media JSON response")
	}
	return nil
}

func (c *MediaClient) get(ctx context.Context, host, path string, q url.Values, out any) error {
	if q == nil {
		q = make(url.Values)
	}
	if c.language != "" {
		q.Set("l", c.language)
	}
	u := url.URL{Scheme: "https", Host: host, Path: path, RawQuery: q.Encode()}
	return mediaJSON(ctx, c.http, u.String(), c.headers, out)
}

type Artwork struct {
	URL        string `json:"url"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	BGColor    string `json:"bgColor,omitempty"`
	TextColor1 string `json:"textColor1,omitempty"`
}

type Preview struct {
	URL     string   `json:"url,omitempty"`
	HLSURL  string   `json:"hlsUrl,omitempty"`
	Artwork *Artwork `json:"artwork,omitempty"`
}

type PlayParams struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	IsLibrary bool   `json:"isLibrary,omitempty"`
	CatalogID string `json:"catalogId,omitempty"`
}

type SongAttributes struct {
	Name                string            `json:"name"`
	ArtistName          string            `json:"artistName"`
	AlbumName           string            `json:"albumName"`
	ComposerName        string            `json:"composerName,omitempty"`
	DurationInMillis    int64             `json:"durationInMillis"`
	ISRC                string            `json:"isrc,omitempty"`
	ReleaseDate         string            `json:"releaseDate,omitempty"`
	GenreNames          []string          `json:"genreNames,omitempty"`
	TrackNumber         int               `json:"trackNumber,omitempty"`
	DiscNumber          int               `json:"discNumber,omitempty"`
	ContentRating       string            `json:"contentRating,omitempty"`
	HasLyrics           *bool             `json:"hasLyrics,omitempty"`
	HasTimeSyncedLyrics *bool             `json:"hasTimeSyncedLyrics,omitempty"`
	AudioTraits         json.RawMessage   `json:"audioTraits,omitempty"` // Android accepts a numeric bitmask or a string array
	Artwork             *Artwork          `json:"artwork,omitempty"`
	URL                 string            `json:"url,omitempty"`
	Previews            []Preview         `json:"previews,omitempty"`
	PlayParams          *PlayParams       `json:"playParams,omitempty"`
	ExtendedAssetURLs   map[string]string `json:"extendedAssetUrls,omitempty"`
	AssetTokens         map[string]string `json:"assetTokens,omitempty"`
	Offers              json.RawMessage   `json:"offers,omitempty"`
}

type Song struct {
	ID            string                     `json:"id"`
	Type          string                     `json:"type"`
	Href          string                     `json:"href,omitempty"`
	Attributes    SongAttributes             `json:"attributes"`
	Relationships map[string]json.RawMessage `json:"relationships,omitempty"`
	Meta          json.RawMessage            `json:"meta,omitempty"`
}

type SongPage struct {
	Data []Song          `json:"data"`
	Next string          `json:"next,omitempty"`
	Href string          `json:"href,omitempty"`
	Meta json.RawMessage `json:"meta,omitempty"`
}

type SearchResponse struct {
	Results struct {
		Songs SongPage `json:"songs"`
	} `json:"results"`
	Meta json.RawMessage `json:"meta,omitempty"`
}

// Android's SearchResultsResponse serializer names the section "song".
// Accept the plural catalog envelope too, without silently dropping either.
func (s *SearchResponse) UnmarshalJSON(data []byte) error {
	var wire struct {
		Results map[string]json.RawMessage `json:"results"`
		Meta    json.RawMessage            `json:"meta"`
	}
	if err := json.Unmarshal(data, &wire); err != nil || wire.Results == nil {
		return errors.New("invalid media search results")
	}
	one, singular := wire.Results["song"]
	items, plural := wire.Results["songs"]
	if singular && plural {
		return errors.New("ambiguous media song section")
	}
	if singular {
		items = one
	}
	*s = SearchResponse{}
	s.Meta = wire.Meta
	if !singular && !plural {
		return nil
	} // a search can return no sections
	if err := json.Unmarshal(items, &s.Results.Songs); err != nil || s.Results.Songs.Data == nil {
		return errors.New("invalid media song section")
	}
	return nil
}

type SearchOptions struct {
	Limit  int
	Offset int
}

func (c *MediaClient) SearchSongs(ctx context.Context, term string, opts SearchOptions) (*SearchResponse, error) {
	if strings.TrimSpace(term) == "" {
		return nil, errors.New("search term required")
	}
	if opts.Limit == 0 {
		opts.Limit = 25
	}
	if opts.Limit < 1 || opts.Limit > 25 || opts.Offset < 0 {
		return nil, errors.New("search limit must be 1..25 and offset nonnegative")
	}
	q := url.Values{"term": {term}, "types": {"songs"}, "limit": {strconv.Itoa(opts.Limit)}, "offset": {strconv.Itoa(opts.Offset)}}
	var out SearchResponse
	if err := c.get(ctx, mediaSearchHost, "/v1/catalog/"+c.storefront+"/search", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type SongOptions struct {
	Include        []string
	ExtendedAssets bool // requests extendedAssetUrls,offers; these are not clear-file guarantees
}

func catalogID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (c *MediaClient) Songs(ctx context.Context, ids []string, opts SongOptions) (*SongPage, error) {
	if len(ids) == 0 || len(ids) > 100 {
		return nil, errors.New("provide 1..100 catalog song IDs")
	}
	for _, id := range ids {
		if !catalogID(id) {
			return nil, errors.New("catalog song IDs must be decimal strings")
		}
	}
	q := url.Values{"ids": {strings.Join(ids, ",")}}
	if len(opts.Include) > 0 {
		q.Set("include", strings.Join(opts.Include, ","))
	}
	if opts.ExtendedAssets {
		q.Set("extend", "extendedAssetUrls,offers")
	}
	var out SongPage
	if err := c.get(ctx, mediaCatalogHost, "/v1/catalog/"+c.storefront+"/songs", q, &out); err != nil {
		return nil, err
	}
	if out.Data == nil {
		return nil, errors.New("media song data missing")
	}
	return &out, nil
}

// Suggestions uses the APK's /search/suggestions route. The heterogeneous
// suggestion payload is preserved rather than forced into a song schema.
func (c *MediaClient) Suggestions(ctx context.Context, term string) (json.RawMessage, error) {
	if strings.TrimSpace(term) == "" {
		return nil, errors.New("search term required")
	}
	var out json.RawMessage
	err := c.get(ctx, mediaSearchHost, "/v1/catalog/"+c.storefront+"/search/suggestions", url.Values{"term": {term}}, &out)
	return out, err
}

// NextSongs follows only same-storefront catalog paths on known AMP hosts.
// This prevents a server-supplied next URL from forwarding the bearer elsewhere.
func (c *MediaClient) NextSongs(ctx context.Context, next string) (*SongPage, error) {
	u, err := url.Parse(next)
	if err != nil || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid media next URL")
	}
	if u.Host == "" {
		if u.Scheme != "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
			return nil, errors.New("invalid media next URL")
		}
		u.Scheme, u.Host = "https", mediaCatalogHost
		if u.Path == "/v1/catalog/"+c.storefront+"/search" || strings.HasPrefix(u.Path, "/v1/catalog/"+c.storefront+"/search/") {
			u.Host = mediaSearchHost
		}
	}
	if u.Scheme != "https" || (u.Host != mediaCatalogHost && u.Host != mediaSearchHost) || !strings.HasPrefix(u.Path, "/v1/catalog/"+c.storefront+"/") || strings.Contains(u.Path, "..") || strings.Contains(u.Path, "\\") {
		return nil, errors.New("untrusted media next URL")
	}
	// Search pagination uses a results.songs envelope; relationship pagination
	// uses a top-level data envelope.
	var raw json.RawMessage
	if err := mediaJSON(ctx, c.http, u.String(), c.headers, &raw); err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, errors.New("invalid media page")
	}
	if _, ok := envelope["results"]; ok {
		var search SearchResponse
		if err := json.Unmarshal(raw, &search); err != nil {
			return nil, errors.New("invalid media page")
		}
		return &search.Results.Songs, nil
	}
	var out SongPage
	if err := json.Unmarshal(raw, &out); err != nil || out.Data == nil {
		return nil, errors.New("invalid media page")
	}
	return &out, nil
}
