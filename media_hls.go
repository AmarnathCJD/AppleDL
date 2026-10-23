package applemusic

import (
	"bufio"
	"errors"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// HLSManifest inventories a single playlist. It does not download child
// playlists, acquire keys, decrypt segments, or establish playability.
type HLSManifest struct {
	Variants              []HLSVariant   `json:"variants,omitempty"`
	Renditions            []HLSRendition `json:"renditions,omitempty"`
	Segments              []HLSSegment   `json:"segments,omitempty"`
	Keys                  []HLSKey       `json:"keys,omitempty"`
	Maps                  []HLSMap       `json:"maps,omitempty"`
	EndList               bool           `json:"endList"`
	MediaSequence         int64          `json:"mediaSequence"`
	DiscontinuitySequence int64          `json:"discontinuitySequence"`
	EncryptionSignaled    bool           `json:"encryptionSignaled"`
	UnhandledTags         []string       `json:"unhandledTags,omitempty"`
}
type HLSVariant struct {
	URL       string
	Bandwidth int64
	Codecs    string
	Audio     string
}
type HLSRendition struct {
	URL     string
	Type    string
	GroupID string
	Name    string
}
type HLSKey struct {
	Method   string
	Format   string
	URI      string
	IV       string
	Session  bool
	Versions string
}
type HLSMap struct {
	URL        string
	ByteRange  string
	Range      *HLSByteRange
	KeyIndices []int
}
type HLSSegment struct {
	URL                   string
	Duration              float64
	ByteRange             string
	Range                 *HLSByteRange
	Sequence              int64
	DiscontinuitySequence int64
	Gap                   bool
	MapIndex              *int
	KeyIndices            []int
}

// HLSByteRange is a resolved offset and byte count, not an HTTP inclusive end.
type HLSByteRange struct{ Offset, Length int64 }

// resolveHLSRange accepts implicit segment offsets only after a ranged segment
// of the same resource. Map offsets must be explicit. These checks are stricter
// than the APK's unchecked rolling offset; they prevent ambiguous acquisition.
func resolveHLSRange(raw, uri, previousURI string, previous *HLSByteRange) (*HLSByteRange, error) {
	if raw == "" {
		return nil, nil
	}
	if !validByteRange(raw) {
		return nil, errors.New("invalid HLS byte range")
	}
	n, off, explicit := strings.Cut(raw, "@")
	length, _ := strconv.ParseInt(n, 10, 64)
	var offset int64
	if explicit {
		offset, _ = strconv.ParseInt(off, 10, 64)
	} else {
		if previous == nil || previousURI != uri {
			return nil, errors.New("ambiguous implicit HLS byte range")
		}
		offset = previous.Offset + previous.Length
	}
	if offset > math.MaxInt64-length {
		return nil, errors.New("HLS byte range overflow")
	}
	return &HLSByteRange{Offset: offset, Length: length}, nil
}

func hlsAttributes(s string) (map[string]string, error) {
	out := make(map[string]string)
	for s != "" {
		i := strings.IndexByte(s, '=')
		if i < 1 {
			return nil, errors.New("invalid HLS attribute")
		}
		key := strings.TrimSpace(s[:i])
		s = s[i+1:]
		var value string
		if strings.HasPrefix(s, "\"") {
			s = s[1:]
			end := strings.IndexByte(s, '"')
			if end < 0 {
				return nil, errors.New("unterminated HLS attribute")
			}
			value, s = s[:end], s[end+1:]
			if s != "" && s[0] != ',' {
				return nil, errors.New("invalid HLS attribute separator")
			}
		} else {
			end := strings.IndexByte(s, ',')
			if end < 0 {
				end = len(s)
			}
			value, s = s[:end], s[end:]
		}
		if _, exists := out[key]; exists {
			return nil, errors.New("duplicate HLS attribute")
		}
		out[key] = value
		s = strings.TrimSpace(strings.TrimPrefix(s, ","))
	}
	return out, nil
}

func hlsURL(base *url.URL, ref string, key bool) (string, error) {
	u, err := url.Parse(ref)
	if err != nil || ref == "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("invalid HLS URI")
	}
	u = base.ResolveReference(u)
	if key && (u.Scheme == "skd" || u.Scheme == "data") {
		return u.String(), nil
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", errors.New("HLS resource must use HTTPS")
	}
	return u.String(), nil
}

func validByteRange(s string) bool {
	parts := strings.Split(s, "@")
	if len(parts) > 2 {
		return false
	}
	n, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || n <= 0 {
		return false
	}
	if len(parts) == 2 {
		off, err := strconv.ParseInt(parts[1], 10, 64)
		return err == nil && off >= 0 && off <= math.MaxInt64-n
	}
	return true
}

func ParseHLS(r io.Reader, baseURL string) (*HLSManifest, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.Fragment != "" {
		return nil, errors.New("invalid HLS base URL")
	}
	lr := &io.LimitedReader{R: r, N: maxResponseBytes + 1}
	s := bufio.NewScanner(lr)
	s.Buffer(make([]byte, 4096), 128<<10)
	if !s.Scan() || strings.TrimPrefix(strings.TrimSpace(s.Text()), "\ufeff") != "#EXTM3U" {
		return nil, errors.New("HLS header missing")
	}
	out := &HLSManifest{}
	var variant map[string]string
	duration := -1.0
	byteRange := ""
	activeKeys := []int(nil)
	var activeMap *int
	var previousRange *HLSByteRange
	previousURI := ""
	discontinuity := int64(0)
	gap, sequenceSeen, discontinuitySeen := false, false, false
	seenUnhandled := map[string]bool{}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			uri, err := hlsURL(base, line, false)
			if err != nil {
				return nil, err
			}
			if variant != nil {
				bw, err := strconv.ParseInt(variant["BANDWIDTH"], 10, 64)
				if err != nil || bw <= 0 {
					return nil, errors.New("invalid HLS bandwidth")
				}
				out.Variants = append(out.Variants, HLSVariant{uri, bw, variant["CODECS"], variant["AUDIO"]})
				variant = nil
			} else {
				if duration < 0 {
					return nil, errors.New("HLS segment duration missing")
				}
				rng, e := resolveHLSRange(byteRange, uri, previousURI, previousRange)
				if e != nil {
					return nil, e
				}
				if int64(len(out.Segments)) > math.MaxInt64-out.MediaSequence {
					return nil, errors.New("HLS media sequence overflow")
				}
				out.Segments = append(out.Segments, HLSSegment{
					URL: uri, Duration: duration, ByteRange: byteRange, Range: rng,
					Sequence:              out.MediaSequence + int64(len(out.Segments)),
					DiscontinuitySequence: discontinuity, Gap: gap, MapIndex: activeMap,
					KeyIndices: append([]int(nil), activeKeys...),
				})
				previousURI, previousRange = uri, rng
				gap = false
				duration, byteRange = -1, ""
			}
			continue
		}
		tag, value, _ := strings.Cut(line, ":")
		switch tag {
		case "#EXT-X-STREAM-INF":
			if variant != nil || duration >= 0 {
				return nil, errors.New("HLS URI missing")
			}
			variant, err = hlsAttributes(value)
			if err != nil {
				return nil, err
			}
		case "#EXT-X-MEDIA":
			a, err := hlsAttributes(value)
			if err != nil {
				return nil, err
			}
			uri := ""
			if a["URI"] != "" {
				uri, err = hlsURL(base, a["URI"], false)
				if err != nil {
					return nil, err
				}
			}
			out.Renditions = append(out.Renditions, HLSRendition{uri, a["TYPE"], a["GROUP-ID"], a["NAME"]})
		case "#EXT-X-KEY", "#EXT-X-SESSION-KEY":
			a, err := hlsAttributes(value)
			if err != nil {
				return nil, err
			}
			method, format := a["METHOD"], a["KEYFORMAT"]
			if method == "" {
				return nil, errors.New("HLS key method missing")
			}
			if format == "" {
				format = "identity"
			}
			uri := ""
			if method != "NONE" {
				uri, err = hlsURL(base, a["URI"], true)
				if err != nil {
					return nil, err
				}
				out.EncryptionSignaled = true
			}
			session := tag == "#EXT-X-SESSION-KEY"
			if method == "NONE" && (session || len(a) != 1) {
				return nil, errors.New("invalid HLS unencrypted key declaration")
			}
			versions := a["KEYFORMATVERSIONS"]
			if versions == "" {
				versions = "1"
			}
			index := len(out.Keys)
			out.Keys = append(out.Keys, HLSKey{Method: method, Format: format, URI: uri, IV: a["IV"], Session: session, Versions: versions})
			if !session {
				if method == "NONE" {
					activeKeys = nil
				} else {
					replaced := false
					for i, k := range activeKeys {
						if out.Keys[k].Format == format {
							activeKeys[i], replaced = index, true
							break
						}
					}
					if !replaced {
						activeKeys = append(activeKeys, index)
					}
				}
			}
		case "#EXT-X-MAP":
			a, err := hlsAttributes(value)
			if err != nil {
				return nil, err
			}
			uri, err := hlsURL(base, a["URI"], false)
			if err != nil {
				return nil, err
			}
			if a["BYTERANGE"] != "" && !validByteRange(a["BYTERANGE"]) {
				return nil, errors.New("invalid HLS map byte range")
			}
			rng, err := resolveHLSRange(a["BYTERANGE"], uri, "", nil)
			if err != nil {
				return nil, err
			}
			index := len(out.Maps)
			out.Maps = append(out.Maps, HLSMap{URL: uri, ByteRange: a["BYTERANGE"], Range: rng, KeyIndices: append([]int(nil), activeKeys...)})
			activeMap = &index
		case "#EXTINF":
			if duration >= 0 || variant != nil {
				return nil, errors.New("HLS URI missing")
			}
			n, _, _ := strings.Cut(value, ",")
			duration, err = strconv.ParseFloat(n, 64)
			if err != nil || duration < 0 || math.IsNaN(duration) || math.IsInf(duration, 0) {
				return nil, errors.New("invalid HLS duration")
			}
		case "#EXT-X-BYTERANGE":
			if byteRange != "" || !validByteRange(value) {
				return nil, errors.New("invalid HLS byte range")
			}
			byteRange = value
		case "#EXT-X-MEDIA-SEQUENCE":
			if sequenceSeen || len(out.Segments) != 0 {
				return nil, errors.New("misplaced HLS media sequence")
			}
			sequenceSeen = true
			out.MediaSequence, err = strconv.ParseInt(value, 10, 64)
			if err != nil || out.MediaSequence < 0 {
				return nil, errors.New("invalid HLS media sequence")
			}
		case "#EXT-X-DISCONTINUITY-SEQUENCE":
			if discontinuitySeen || len(out.Segments) != 0 || discontinuity != 0 {
				return nil, errors.New("misplaced HLS discontinuity sequence")
			}
			discontinuitySeen = true
			out.DiscontinuitySequence, err = strconv.ParseInt(value, 10, 64)
			if err != nil || out.DiscontinuitySequence < 0 {
				return nil, errors.New("invalid HLS discontinuity sequence")
			}
			discontinuity = out.DiscontinuitySequence
		case "#EXT-X-DISCONTINUITY":
			if discontinuity == math.MaxInt64 {
				return nil, errors.New("HLS discontinuity sequence overflow")
			}
			discontinuity++
		case "#EXT-X-GAP":
			gap = true
		case "#EXT-X-ENDLIST":
			out.EndList = true
		case "#EXT-X-VERSION", "#EXT-X-TARGETDURATION", "#EXT-X-PLAYLIST-TYPE", "#EXT-X-INDEPENDENT-SEGMENTS":
		default:
			if strings.HasPrefix(tag, "#EXT") && !seenUnhandled[tag] {
				out.UnhandledTags = append(out.UnhandledTags, tag)
				seenUnhandled[tag] = true
			}
		}
	}
	if s.Err() != nil {
		return nil, errors.New("read HLS playlist failed or line too long")
	}
	if lr.N <= 0 {
		return nil, errors.New("HLS playlist exceeds size limit")
	}
	if variant != nil || duration >= 0 || byteRange != "" || gap {
		return nil, errors.New("HLS trailing URI missing")
	}
	if len(out.Variants) == 0 && len(out.Segments) == 0 {
		return nil, errors.New("HLS playlist has no variants or segments")
	}
	if len(out.Variants) > 0 && len(out.Segments) > 0 {
		return nil, errors.New("HLS mixes master and media entries")
	}
	return out, nil
}
