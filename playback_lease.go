package applemusic

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"howett.net/plist"
)

type LeaseAction string

const (
	LeaseStart    LeaseAction = "lease-start"
	LeaseDownload LeaseAction = "lease-download"
	LeaseRenew    LeaseAction = "lease-renew"
)

// NativeTransaction identifies FairPlayGenerateSubscriptionBagRequest's mode.
// The caller must supply native device material from ADI context -1.
func (a LeaseAction) NativeTransaction() (int, error) {
	switch a {
	case LeaseStart, LeaseDownload:
		return 308, nil
	case LeaseRenew:
		return 310, nil
	default:
		return 0, errors.New("invalid lease action")
	}
}

type LeasePayload struct {
	GUID          string      `json:"guid,omitempty"`
	SBSync        string      `json:"sbsync,omitempty"`
	Action        LeaseAction `json:"action"`
	SalableAdamID string      `json:"salableAdamId,omitempty"`
}

// NewLeasePayload encodes the opaque native subscription bag bytes as Base64.
// Their internal format has not been established; this is not a plist encoder.
func NewLeasePayload(guid string, action LeaseAction, itemID *int64, nativeBag []byte) (LeasePayload, error) {
	if _, err := action.NativeTransaction(); err != nil {
		return LeasePayload{}, err
	}
	p := LeasePayload{GUID: guid, SBSync: base64.StdEncoding.EncodeToString(nativeBag), Action: action}
	if itemID != nil {
		p.SalableAdamID = strconv.FormatInt(*itemID, 10)
	}
	return p, nil
}

// SignedBytes preserves Kotlin ByteArray's JSON signed-integer representation.
// On the wire, lease SINF data arrives as XML plist <data>; the app normalizes it.
type SignedBytes []byte

func (b SignedBytes) MarshalJSON() ([]byte, error) {
	values := make([]int8, len(b))
	for i, v := range b {
		values[i] = int8(v)
	}
	return json.Marshal(values)
}

func (b *SignedBytes) UnmarshalJSON(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '[' {
		return errors.New("SINF data must be a signed byte array")
	}
	var values []*int8
	if err := json.Unmarshal(data, &values); err != nil {
		return errors.New("invalid SINF signed byte array")
	}
	decoded := make([]byte, len(values))
	for i, v := range values {
		if v == nil {
			return errors.New("null SINF byte")
		}
		decoded[i] = byte(*v)
	}
	*b = decoded
	return nil
}

type PlaybackSINF struct {
	ID    *int32      `json:"id"`
	SINF  SignedBytes `json:"sinf"`
	SINF2 SignedBytes `json:"sinf2"`
}

func (s *PlaybackSINF) UnmarshalJSON(data []byte) error {
	if err := requiredPlaybackFields(data, "sinf", "sinf2"); err != nil {
		return err
	}
	type plain PlaybackSINF
	return decodePlaybackObject(data, (*plain)(s))
}

type PlaybackAsset struct {
	URL         *string        `json:"URL"`
	ArtworkURL  *string        `json:"artworkURL"`
	DownloadKey *string        `json:"downloadKey"`
	FileSize    *int64         `json:"file-size"`
	Flavor      *string        `json:"flavor"`
	MD5         *string        `json:"md5"`
	SINFs       []PlaybackSINF `json:"sinfs"`
}

func (a *PlaybackAsset) UnmarshalJSON(data []byte) error {
	if err := requiredPlaybackFields(data, "URL", "flavor"); err != nil {
		return err
	}
	type plain PlaybackAsset
	return decodePlaybackObject(data, (*plain)(a))
}

type PlaybackItem struct {
	AudioTraits         []string        `json:"audioTraits"`
	Assets              []PlaybackAsset `json:"assets"`
	HLSCertificateURL   *string         `json:"hls-key-cert-url"`
	HLSKeyServerURL     *string         `json:"hls-key-server-url"`
	HLSPlaylistURL      *string         `json:"hls-playlist-url"`
	IsITunesStream      *bool           `json:"is-itunes-stream"`
	KeyServerProtocol   *string         `json:"key-server-protocol-type"`
	KeySeverProtocol    *string         `json:"key-sever-protocol-type"` // APK spelling; distinct field.
	MPHLSCertificateURL *string         `json:"mp-hls-key-cert-url"`
	MPHLSKeyServerURL   *string         `json:"mp-hls-key-server-url"`
	MPHLSPlaylistURL    *string         `json:"mp-hls-playlist-url"`
	SongID              int64           `json:"songId"`
}

func (p *PlaybackItem) UnmarshalJSON(data []byte) error {
	if err := requiredPlaybackFields(data, "songId"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	if bytes.Equal(bytes.TrimSpace(fields["songId"]), []byte("null")) {
		return errors.New("songId cannot be null")
	}
	type plain PlaybackItem
	return decodePlaybackObject(data, (*plain)(p))
}

// Kotlin matches wire field names exactly and ignores unknown object fields.
// encoding/json alone would also accept case-insensitive aliases.
func decodePlaybackObject(data []byte, target any) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return errors.New("invalid playback object")
	}
	typ := reflect.TypeOf(target).Elem()
	known := make(map[string]json.RawMessage, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Tag.Get("json")
		if raw, ok := fields[name]; ok {
			known[name] = raw
		}
	}
	filtered, err := json.Marshal(known)
	if err != nil {
		return err
	}
	return json.Unmarshal(filtered, target)
}

func requiredPlaybackFields(data []byte, names ...string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return errors.New("invalid playback object")
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("required playback field missing: %s", name)
		}
	}
	return nil
}

type LeaseResponse struct {
	KeyBag                 *string         `json:"keybag"`
	SubKeyBag              *string         `json:"subKeyBag"`
	LeaseDurationInSeconds float64         `json:"leaseDurationInSeconds"`
	CKC                    *string         `json:"ckc"`
	OfflineSlotAvailable   *bool           `json:"offlineSlotAvailable"`
	SongList               []PlaybackItem  `json:"songList"`
	Status                 *float64        `json:"status"`
	FailureType            *int32          `json:"failureType"`
	Error                  json.RawMessage `json:"error"` // StoreErrorCondition remains opaque.
	HTTPStatusCode         *int32          `json:"httpStatusCode"`
}

// LeaseFailure intentionally excludes server messages and account-specific data.
type LeaseFailure struct{ Code int32 }

func (e *LeaseFailure) Error() string { return fmt.Sprintf("lease failure %d", e.Code) }

// CheckFailure mirrors DefaultLeaseRequestExecutor: non-null failureType fails,
// including zero. Absence of failure does not mean native keybag import succeeded.
func (r *LeaseResponse) CheckFailure() error {
	if r.FailureType != nil {
		return &LeaseFailure{*r.FailureType}
	}
	return nil
}

// ParseLeaseResponseJSON consumes the app's intermediate normalized model form.
// The observed HTTP lease response uses XML plist, not JSON.
func ParseLeaseResponseJSON(data []byte) (*LeaseResponse, error) {
	if len(data) > maxResponseBytes || requiredPlaybackFields(data) != nil {
		return nil, errors.New("invalid lease response")
	}
	status, httpStatus := 0.0, int32(-1)
	r := LeaseResponse{LeaseDurationInSeconds: 600, SongList: []PlaybackItem{}, Status: &status, HTTPStatusCode: &httpStatus}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	if bytes.Equal(bytes.TrimSpace(fields["leaseDurationInSeconds"]), []byte("null")) {
		return nil, errors.New("invalid lease duration")
	}
	if err := decodePlaybackObject(data, &r); err != nil {
		return nil, errors.New("invalid lease response fields")
	}
	return &r, nil
}

func normalizePlaybackPlist(v any) any {
	switch x := v.(type) {
	case []byte:
		return SignedBytes(x)
	case []any:
		for i := range x {
			x[i] = normalizePlaybackPlist(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = normalizePlaybackPlist(x[k])
		}
	}
	return v
}

func ParseLeaseResponseXML(data []byte) (*LeaseResponse, error) {
	if len(data) > maxResponseBytes {
		return nil, errors.New("lease response exceeds size limit")
	}
	var fields map[string]any
	format, err := plist.Unmarshal(data, &fields)
	if err != nil || format != plist.XMLFormat || fields == nil {
		return nil, errors.New("invalid lease XML plist")
	}
	normalized, err := json.Marshal(normalizePlaybackPlist(fields))
	if err != nil {
		return nil, errors.New("invalid lease plist values")
	}
	return ParseLeaseResponseJSON(normalized)
}
