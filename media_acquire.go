package applemusic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const MaxHLSResourceBytes int64 = 32 << 20
const MaxHLSAcquisitionBytes int64 = 256 << 20

// Authenticated AOD child playlists were observed to reference ranged .mp4
// resources on the same service. Keep this exception separate from previews.
func validateMediaResourceLocation(raw string) error {
	if _, err := validateCDN(raw); err == nil {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "aod.itunes.apple.com") || u.User != nil || u.Fragment != "" || !strings.HasSuffix(u.EscapedPath(), ".mp4") {
		return errors.New("unsupported Apple media resource location")
	}
	return nil
}

func mediaResourceClient(hc *http.Client) *http.Client {
	c := newMediaHTTP(hc)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return errors.New("media resource redirect limit")
		}
		return validateMediaResourceLocation(req.URL.String())
	}
	return c
}

// FetchMediaResource implements the bounded GET/read branch of the APK's
// PlayerHttpDataSource: inclusive position+length request end, skip position on
// HTTP 200, and expose at most Length bytes. A response must contain all requested
// bytes. Redirects are restricted to the media CDN; account cookies are omitted.
// This transfers bytes, including ciphertext. It does not fetch keys or decrypt.
// maxBytes bounds the returned data AND any prefix skipped after HTTP 200.
func FetchMediaResource(ctx context.Context, hc *http.Client, rawURL string, options FileRequestOptions, maxBytes int64) ([]byte, error) {
	if maxBytes < 1 || maxBytes > MaxHLSResourceBytes || options.Length == 0 || options.AllowGzip || options.Length > maxBytes {
		return nil, errors.New("unsupported bounded media resource options")
	}
	if err := validateMediaResourceLocation(rawURL); err != nil {
		return nil, err
	}
	p, err := PlanFileRequest(rawURL, options)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, nil)
	if err != nil {
		return nil, errors.New("invalid media resource request")
	}
	req.Header = p.Headers.Clone()
	resp, err := mediaResourceClient(hc).Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("media resource transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, &MediaHTTPError{resp.StatusCode}
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return nil, errors.New("encoded media resource not supported")
	}
	remaining := maxBytes
	declared := resp.ContentLength
	if resp.StatusCode == http.StatusPartialContent {
		start, end, total, e := parseMediaContentRange(resp.Header.Get("Content-Range"))
		if e != nil || start != options.Position || p.Headers.Get("Range") == "" {
			return nil, errors.New("media content range mismatch")
		}
		count := end - start + 1
		if options.Length >= 0 && count > options.Length+1 {
			return nil, errors.New("media range exceeds requested end")
		}
		if options.Length == -1 && (total < 0 || end+1 != total) {
			return nil, errors.New("media open range does not reach resource end")
		}
		if declared >= 0 && declared != count {
			return nil, errors.New("media content length mismatch")
		}
		if options.Length >= 0 && count < options.Length {
			return nil, errors.New("media range is truncated")
		}
		declared = count
	} else if options.Position > 0 {
		if options.Position >= remaining || (options.Length >= 0 && options.Length > remaining-options.Position) {
			return nil, errors.New("media skipped prefix exceeds size limit")
		}
		if _, err := io.CopyN(io.Discard, resp.Body, options.Position); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("media skipped prefix is truncated")
		}
		remaining -= options.Position
		if declared >= 0 {
			declared -= options.Position
			if declared < 0 {
				return nil, errors.New("media content length mismatch")
			}
		}
	}
	if options.Length >= 0 {
		if options.Length > remaining {
			return nil, errors.New("media resource exceeds size limit")
		}
		if declared >= 0 && declared < options.Length {
			return nil, errors.New("media resource is truncated")
		}
		data := make([]byte, int(options.Length))
		if _, err := io.ReadFull(resp.Body, data); err != nil {
			clear(data)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("media resource is truncated")
		}
		if ctx.Err() != nil {
			clear(data)
			return nil, ctx.Err()
		}
		return data, nil
	}
	if declared > remaining {
		return nil, errors.New("media resource exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, remaining+1))
	if err != nil || int64(len(data)) > remaining || len(data) == 0 || (declared >= 0 && int64(len(data)) != declared) {
		clear(data)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("media resource incomplete or exceeds size limit")
	}
	if ctx.Err() != nil {
		clear(data)
		return nil, ctx.Err()
	}
	return data, nil
}

func parseMediaContentRange(value string) (int64, int64, int64, error) {
	bad := errors.New("invalid media content range")
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, bad
	}
	rangePart, totalPart, ok := strings.Cut(strings.TrimPrefix(value, "bytes "), "/")
	if !ok {
		return 0, 0, 0, bad
	}
	startPart, endPart, ok := strings.Cut(rangePart, "-")
	if !ok {
		return 0, 0, 0, bad
	}
	start, e1 := strconv.ParseInt(startPart, 10, 64)
	end, e2 := strconv.ParseInt(endPart, 10, 64)
	if e1 != nil || e2 != nil || start < 0 || end < start || end == math.MaxInt64 {
		return 0, 0, 0, bad
	}
	total := int64(-1)
	if totalPart != "*" {
		var e error
		total, e = strconv.ParseInt(totalPart, 10, 64)
		if e != nil || total <= end {
			return 0, 0, 0, bad
		}
	}
	return start, end, total, nil
}

type HLSAcquisitionOptions struct {
	UserAgent, Language, PlaybackSessionID string
	MaxBytes                               int64 // Saved-byte budget; 0 selects MaxHLSAcquisitionBytes.
}

// HLSAcquiredFile names only local files. It contains no signed URLs or key data.
type HLSAcquiredFile struct {
	Name                  string `json:"name"`
	Size                  int64  `json:"size"`
	SHA256                string `json:"sha256"`
	Initialization        bool   `json:"initialization"`
	SegmentIndex          int    `json:"segmentIndex"` // -1 for an initialization file.
	MapIndex              *int   `json:"mapIndex,omitempty"`
	KeyIndices            []int  `json:"keyIndices,omitempty"`
	Sequence              int64  `json:"sequence,omitempty"`
	DiscontinuitySequence int64  `json:"discontinuitySequence,omitempty"`
}

type HLSAcquisitionReceipt struct {
	Files              []HLSAcquiredFile `json:"files"`
	TotalBytes         int64             `json:"totalBytes"`
	DurationSeconds    float64           `json:"durationSeconds"`
	SegmentCount       int               `json:"segmentCount"`
	EncryptionSignaled bool              `json:"encryptionSignaled"`
	Decrypted          bool              `json:"decrypted"` // Always false for this acquisition API.
}

// AcquireHLS saves every segment and referenced initialization section from one
// completed media playlist. It does not select variants, concatenate, decrypt,
// license, decode or follow key URIs. Use a trusted catalog-derived playlist.
// Destination must not exist. Errors leave completed files for inspection; only
// a final complete.json receipt marks success. No retries or overwrites occur.
func AcquireHLS(ctx context.Context, hc *http.Client, m *HLSManifest, destination string, options HLSAcquisitionOptions) (*HLSAcquisitionReceipt, error) {
	if m == nil || !m.EndList || len(m.Segments) == 0 || len(m.Variants) != 0 || len(m.Renditions) != 0 || len(m.UnhandledTags) != 0 || len(m.Segments) > 10000 {
		return nil, errors.New("acquisition requires a completed supported HLS media playlist")
	}
	maxBytes := options.MaxBytes
	if maxBytes == 0 {
		maxBytes = MaxHLSAcquisitionBytes
	}
	if maxBytes < 1 || maxBytes > MaxHLSAcquisitionBytes {
		return nil, errors.New("invalid HLS acquisition size limit")
	}
	fileOptions := func(r *HLSByteRange) FileRequestOptions {
		o := FileRequestOptions{UserAgent: options.UserAgent, Language: options.Language, PlaybackSessionID: options.PlaybackSessionID, Length: -1}
		if r != nil {
			o.Position, o.Length = r.Offset, r.Length
		}
		return o
	}
	validate := func(uri, rawRange string, r *HLSByteRange, keys []int) error {
		if strings.Contains(uri, "{$") {
			return errors.New("unresolved HLS variable")
		}
		if err := validateMediaResourceLocation(uri); err != nil {
			return err
		}
		if (rawRange != "") != (r != nil) || (r != nil && (r.Length <= 0 || r.Length > MaxHLSResourceBytes)) {
			return errors.New("invalid HLS acquisition byte range")
		}
		if _, err := PlanFileRequest(uri, fileOptions(r)); err != nil {
			return err
		}
		for _, i := range keys {
			if i < 0 || i >= len(m.Keys) || m.Keys[i].Session || m.Keys[i].Method == "NONE" {
				return errors.New("invalid HLS key association")
			}
		}
		return nil
	}
	// Preflight the entire selection before creating files or making requests.
	duration := 0.0
	for _, s := range m.Segments {
		duration += s.Duration
		if s.Gap || s.Sequence < 0 || s.DiscontinuitySequence < 0 || math.IsNaN(s.Duration) || math.IsInf(duration, 0) || s.Duration < 0 {
			return nil, errors.New("unsupported HLS segment state")
		}
		if err := validate(s.URL, s.ByteRange, s.Range, s.KeyIndices); err != nil {
			return nil, err
		}
		if s.MapIndex != nil {
			if *s.MapIndex < 0 || *s.MapIndex >= len(m.Maps) {
				return nil, errors.New("invalid HLS initialization association")
			}
			init := m.Maps[*s.MapIndex]
			if err := validate(init.URL, init.ByteRange, init.Range, init.KeyIndices); err != nil {
				return nil, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return nil, errors.New("cannot create new HLS acquisition directory")
	}
	receipt := &HLSAcquisitionReceipt{EncryptionSignaled: m.EncryptionSignaled}
	save := func(uri string, r *HLSByteRange, f HLSAcquiredFile) error {
		limit := maxBytes - receipt.TotalBytes
		if limit > MaxHLSResourceBytes {
			limit = MaxHLSResourceBytes
		}
		data, err := FetchMediaResource(ctx, hc, uri, fileOptions(r), limit)
		if err != nil {
			return err
		}
		defer clear(data)
		if err := writeAcquiredFile(filepath.Join(destination, f.Name), data); err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		f.Size, f.SHA256 = int64(len(data)), hex.EncodeToString(digest[:])
		receipt.TotalBytes += f.Size
		receipt.Files = append(receipt.Files, f)
		return nil
	}
	savedMaps := map[int]bool{}
	for i, s := range m.Segments {
		if s.MapIndex != nil && !savedMaps[*s.MapIndex] {
			index := *s.MapIndex
			init := m.Maps[index]
			if err := save(init.URL, init.Range, HLSAcquiredFile{Name: fmt.Sprintf("init-%04d.bin", index), Initialization: true, SegmentIndex: -1, MapIndex: &index, KeyIndices: append([]int(nil), init.KeyIndices...)}); err != nil {
				return nil, err
			}
			savedMaps[index] = true
		}
		if err := save(s.URL, s.Range, HLSAcquiredFile{Name: fmt.Sprintf("segment-%06d.bin", i), SegmentIndex: i, MapIndex: s.MapIndex, KeyIndices: append([]int(nil), s.KeyIndices...), Sequence: s.Sequence, DiscontinuitySequence: s.DiscontinuitySequence}); err != nil {
			return nil, err
		}
		receipt.SegmentCount++
		receipt.DurationSeconds += s.Duration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, errors.New("cannot encode HLS acquisition receipt")
	}
	if err := writeAcquiredFile(filepath.Join(destination, "complete.json"), data); err != nil {
		return nil, err
	}
	return receipt, nil
}

func writeAcquiredFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create new acquired file")
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		_ = os.Remove(path)
		return errors.New("cannot finish acquired file")
	}
	return nil
}
