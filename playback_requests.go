package applemusic

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// StoreHeaderValues must belong to the same account and request URL. Cookie is
// already URL/account-scoped. These values never imply completed signing.
type StoreHeaderValues struct {
	UserAgent, Locale, Storefront, Cookie, XToken string
	DSID                                          int64
}

// StoreAcceptLanguage follows the verified simple JADX branch: Chinese script
// replacement occurs only when the input contained an underscore.
func StoreAcceptLanguage(locale string) string {
	if !strings.Contains(locale, "_") {
		return locale
	}
	locale = strings.ReplaceAll(locale, "_", "-")
	switch strings.ToLower(locale) {
	case "zh-cn":
		return "zh-Hans"
	case "zh-tw", "zh-hk":
		return "zh-Hant"
	}
	return locale
}

func (s StoreHeaderValues) Headers() (http.Header, error) {
	h := http.Header{}
	h.Set("User-Agent", s.UserAgent)
	h.Set("Accept", "*/*")
	h.Set("Accept-Language", StoreAcceptLanguage(s.Locale))
	if s.DSID != 0 {
		h.Set("X-Dsid", strconv.FormatInt(s.DSID, 10))
	}
	for k, v := range map[string]string{"X-Apple-Store-Front": s.Storefront, "Cookie": s.Cookie, "X-Token": s.XToken} {
		if v != "" {
			h.Set(k, v)
		}
	}
	return h, validatePlaybackHeaders(h)
}

func validatePlaybackHeaders(h http.Header) error {
	for _, values := range h {
		for _, v := range values {
			for _, c := range v {
				if c == 127 || c < 32 && c != '\t' {
					return errors.New("invalid playback header value")
				}
			}
		}
	}
	return nil
}

// PlaybackRequestPlan is an offline application-layer snapshot. Body, URL and
// headers can contain credentials/signed material; do not log or send them in
// reports. No method on this type transmits it. StorePreparationRequired means
// bag-driven device/integrity/FPDI/Mescal decorators remain to be applied.
type PlaybackRequestPlan struct {
	Method, URL              string
	Headers                  http.Header
	Body                     []byte
	ConnectTimeout           time.Duration
	ReadTimeout              time.Duration
	StorePreparationRequired bool
}

func playbackEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid playback HTTPS endpoint")
	}
	return nil
}

func storePlaybackPlan(endpoint, method string, headers StoreHeaderValues, body []byte) (*PlaybackRequestPlan, error) {
	if err := playbackEndpoint(endpoint); err != nil {
		return nil, err
	}
	h, err := headers.Headers()
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		h.Set("Content-Type", "application/json")
	}
	return &PlaybackRequestPlan{Method: method, URL: endpoint, Headers: h, Body: body, StorePreparationRequired: true}, nil
}

// PlanLeaseRequest takes the subDownload URL from the playback bag.
func PlanLeaseRequest(endpoint string, headers StoreHeaderValues, payload LeasePayload) (*PlaybackRequestPlan, error) {
	if _, err := payload.Action.NativeTransaction(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	p, err := storePlaybackPlan(endpoint, http.MethodPost, headers, body)
	if err == nil {
		p.ConnectTimeout, p.ReadTimeout = 4*time.Second, 4*time.Second
	}
	return p, err
}

func PlanCertificateRequest(endpoint, guid string, headers StoreHeaderValues) (*PlaybackRequestPlan, error) {
	p, err := storePlaybackPlan(endpoint, http.MethodGet, headers, nil)
	if err != nil {
		return nil, err
	}
	p.Headers.Set("X-Guid", guid)
	if err := validatePlaybackHeaders(p.Headers); err != nil {
		return nil, err
	}
	return p, nil
}

func PlanLicenseRequest(endpoint string, headers StoreHeaderValues, signedOutDSID int64, request LicenseRequest) (*PlaybackRequestPlan, error) {
	body, err := request.Body()
	if err != nil {
		return nil, err
	}
	p, err := storePlaybackPlan(endpoint, http.MethodPost, headers, body)
	if err != nil {
		return nil, err
	}
	p.Headers.Set("X-Guid", request.GUID)
	dsid := headers.DSID
	if dsid <= 0 {
		dsid = signedOutDSID
	}
	p.Headers.Set("X-Secure-Invalidation-Dsid", strconv.FormatInt(dsid, 10))
	if err := validatePlaybackHeaders(p.Headers); err != nil {
		return nil, err
	}
	return p, nil
}

type MiniSINFPayload struct {
	GUID    string   `json:"guid"`
	Flavors []string `json:"flavors"`
	AdamIDs []string `json:"adamIds"`
}

// PlanMiniSINFRequest takes fetchSinfs from the bag. It handles one batch;
// APK batching/version negotiation has not been ported.
func PlanMiniSINFRequest(endpoint string, headers StoreHeaderValues, payload MiniSINFPayload) (*PlaybackRequestPlan, error) {
	if payload.Flavors == nil {
		payload.Flavors = []string{}
	}
	if payload.AdamIDs == nil {
		payload.AdamIDs = []string{}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return storePlaybackPlan(endpoint, http.MethodPost, headers, body)
}

func ParseMiniSINFResponse(data []byte) (map[string]map[string]string, error) {
	if len(data) > maxResponseBytes || requiredPlaybackFields(data) != nil {
		return nil, errors.New("invalid mini-SINF response")
	}
	var result map[string]map[string]string
	if json.Unmarshal(data, &result) != nil {
		return nil, errors.New("invalid mini-SINF entries")
	}
	// Local validation: avoid silently turning a JSON null into an empty SINF.
	var raw map[string]map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return nil, errors.New("invalid mini-SINF entries")
	}
	for _, flavors := range raw {
		if flavors == nil {
			return nil, errors.New("null mini-SINF flavor map")
		}
		for _, value := range flavors {
			if strings.TrimSpace(string(value)) == "null" {
				return nil, errors.New("null mini-SINF entry")
			}
		}
	}
	return result, nil
}

type FileRequestOptions struct {
	UserAgent, Language, PlaybackSessionID string
	Position, Length                       int64 // Length=-1 means through EOF.
	AllowGzip                              bool
}

// APKFileRange reproduces PlayerHttpDataSource's observed end=position+length,
// confirmed in both normal and simple decompilation. HTTP end offsets are
// inclusive, so this requests an extra byte. This compatibility function must
// not be used as a standards-correct HLS range calculator.
func APKFileRange(position, length int64) (string, error) {
	if position < 0 || length < -1 || (length >= 0 && position > math.MaxInt64-length) {
		return "", errors.New("invalid file range")
	}
	if position == 0 && length == -1 {
		return "", nil
	}
	r := "bytes=" + strconv.FormatInt(position, 10) + "-"
	if length != -1 {
		r += strconv.FormatInt(position+length, 10)
	}
	return r, nil
}

// PlanFileRequest represents the GET branch of PlayerHttpDataSource. The APK's
// playback CookieManager is separate from store headers; its cookies and
// redirect behavior are not implemented here. TLS verification stays enabled
// in existing Go network clients; the APK trust-all factory is not ported.
func PlanFileRequest(endpoint string, options FileRequestOptions) (*PlaybackRequestPlan, error) {
	if err := playbackEndpoint(endpoint); err != nil {
		return nil, err
	}
	r, err := APKFileRange(options.Position, options.Length)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set("Accept", "*/*")
	h.Set("Accept-Language", options.Language)
	h.Set("User-Agent", options.UserAgent)
	h.Set("X-Playback-Session-Id", options.PlaybackSessionID)
	if !options.AllowGzip {
		h.Set("Accept-Encoding", "identity")
	}
	if r != "" {
		h.Set("Range", r)
	}
	if err := validatePlaybackHeaders(h); err != nil {
		return nil, err
	}
	return &PlaybackRequestPlan{Method: http.MethodGet, URL: endpoint, Headers: h, ConnectTimeout: 4 * time.Second, ReadTimeout: 2 * time.Second}, nil
}
