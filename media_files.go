package applemusic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const MaxPreviewBytes int64 = 32 << 20

type PreviewFile struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Container string `json:"container"`
}

func validateCDN(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return nil, errors.New("invalid Apple media CDN URL")
	}
	h := strings.ToLower(u.Hostname())
	if h != "mzstatic.com" && !strings.HasSuffix(h, ".mzstatic.com") && h != "audio-ssl.itunes.apple.com" {
		return nil, errors.New("unsupported Apple media CDN host")
	}
	return u, nil
}

func cdnClient(hc *http.Client) *http.Client {
	c := newMediaHTTP(hc)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return errors.New("media CDN redirect limit")
		}
		_, err := validateCDN(req.URL.String())
		return err
	}
	return c
}

// DownloadPreview saves the progressive URL from a catalog preview. It neither
// accepts PlayAsset as input nor downloads HLS, licenses or full-track assets.
// Caller must pass a preview returned by a trusted catalog, not an arbitrary URL.
// The file appears only after a complete bounded transfer. Existing files are
// never replaced. The destination filesystem must support hard links (e.g. NTFS).
func DownloadPreview(ctx context.Context, hc *http.Client, preview Preview, destination string) (*PreviewFile, error) {
	u, err := validateCDN(preview.URL)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(strings.ToLower(u.Path), ".m3u8") {
		return nil, errors.New("preview is HLS; inspect the playlist separately")
	}
	if _, err := os.Lstat(destination); err == nil {
		return nil, errors.New("preview destination already exists")
	} else if !os.IsNotExist(err) {
		return nil, errors.New("cannot inspect preview destination")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid preview request")
	}
	req.Header.Set("Accept", "audio/*,application/octet-stream")
	resp, err := cdnClient(hc).Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("preview transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &MediaHTTPError{resp.StatusCode}
	}
	if resp.ContentLength > MaxPreviewBytes {
		return nil, errors.New("preview exceeds size limit")
	}
	contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if !strings.HasPrefix(contentType, "audio/") && contentType != "application/octet-stream" && contentType != "video/mp4" {
		return nil, errors.New("unexpected preview content type")
	}
	reader := bufio.NewReader(resp.Body)
	header, err := reader.Peek(12)
	if err != nil {
		return nil, errors.New("preview is empty or truncated")
	}
	container := ""
	switch {
	case string(header[4:8]) == "ftyp":
		container = "mp4"
	case string(header[:3]) == "ID3" || (header[0] == 0xff && header[1]&0xe0 == 0xe0):
		container = "mpeg-audio"
	default:
		return nil, errors.New("unrecognized preview container")
	}
	f, err := os.CreateTemp(filepath.Dir(destination), ".am-preview-*")
	if err != nil {
		return nil, errors.New("cannot create preview temporary file")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(reader, MaxPreviewBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("preview transfer incomplete")
	}
	if n > MaxPreviewBytes {
		return nil, errors.New("preview exceeds size limit")
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return nil, errors.New("preview length mismatch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.Sync() != nil {
		return nil, errors.New("sync preview file failed")
	}
	if f.Close() != nil {
		return nil, errors.New("close preview file failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Link is an atomic no-replace publication on NTFS and Unix filesystems.
	if os.Link(tmp, destination) != nil {
		return nil, errors.New("publish preview failed; destination exists or filesystem lacks hard links")
	}
	return &PreviewFile{destination, n, hex.EncodeToString(hash.Sum(nil)), container}, nil
}

// validateHLSLocation includes the aod.itunes.apple.com playlist host observed
// in authenticated extendedAssetUrls. This exception is not used for previews.
func validateHLSLocation(raw string) (*url.URL, error) {
	if u, err := validateCDN(raw); err == nil {
		return u, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "aod.itunes.apple.com") || u.User != nil || u.Fragment != "" || !strings.HasSuffix(u.EscapedPath(), ".m3u8") {
		return nil, errors.New("unsupported Apple HLS playlist location")
	}
	return u, nil
}

// FetchHLS fetches just one playlist from Apple's media CDN with no account
// credentials. Child manifests and key URIs are never fetched automatically.
func FetchHLS(ctx context.Context, hc *http.Client, rawURL string) (*HLSManifest, error) {
	u, err := validateHLSLocation(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid HLS request")
	}
	c := newMediaHTTP(hc)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return errors.New("HLS redirect limit")
		}
		_, err := validateHLSLocation(req.URL.String())
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("HLS transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &MediaHTTPError{resp.StatusCode}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if resp.ContentLength > maxResponseBytes {
		return nil, errors.New("HLS playlist exceeds size limit")
	}
	// Read the bounded response before parsing so a truncated quoted attribute
	// cannot conceal a transfer failure or a declared content-length mismatch.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, errors.New("HLS transfer incomplete")
	}
	if len(data) > maxResponseBytes {
		return nil, errors.New("HLS playlist exceeds size limit")
	}
	if resp.ContentLength >= 0 && int64(len(data)) != resp.ContentLength {
		return nil, errors.New("HLS transfer incomplete")
	}
	return ParseHLS(bytes.NewReader(data), resp.Request.URL.String())
}
