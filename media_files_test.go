package applemusic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixturePreview = "\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00M4A fixture-audio-bytes"
const fixturePreviewURL = "https://audio.mzstatic.com/preview.m4a"

type zeroMediaReader struct{}

func (zeroMediaReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestPreviewCompleteNoOverwriteAndCredentials(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(fixturePreviewURL)
	jar.SetCookies(u, []*http.Cookie{{Name: "account", Value: "secret"}})
	calls := 0
	hc := &http.Client{Jar: jar, Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Dsid") != "" {
			t.Fatal("CDN received credentials")
		}
		if calls == 1 {
			resp := mediaResponse(r, 302, "")
			resp.Header.Set("Location", "https://audio-ssl.itunes.apple.com/redirected.m4a")
			return resp, nil
		}
		resp := mediaResponse(r, 200, fixturePreview)
		resp.Header.Set("Content-Type", "audio/mp4")
		return resp, nil
	})}
	dir := t.TempDir()
	dest := filepath.Join(dir, "preview.m4a")
	file, err := DownloadPreview(context.Background(), hc, Preview{URL: fixturePreviewURL}, dest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(fixturePreview))
	if file.SHA256 != hex.EncodeToString(digest[:]) || file.Size != int64(len(fixturePreview)) || file.Container != "mp4" {
		t.Fatal("wrong file receipt")
	}
	if _, err := DownloadPreview(context.Background(), hc, Preview{URL: fixturePreviewURL}, dest); err == nil {
		t.Fatal("overwrote existing file")
	}
	b, err := os.ReadFile(dest)
	if err != nil || string(b) != fixturePreview || calls != 2 {
		t.Fatal("existing file changed")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary file remains")
	}
}

func TestPreviewFailuresLeaveNoPublishedFile(t *testing.T) {
	for _, scenario := range []string{"length", "partial-read", "oversize-header", "oversize-stream", "bad-mime", "bad-container", "forbidden-redirect", "cancelled", "destination-race"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			dest := filepath.Join(dir, "preview.m4a")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			hc := &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				resp := mediaResponse(r, 200, fixturePreview)
				resp.Header.Set("Content-Type", "audio/mp4")
				switch scenario {
				case "length":
					resp.ContentLength++
				case "partial-read":
					resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(fixturePreview), mediaBrokenReader{}))
				case "oversize-header":
					resp.ContentLength = MaxPreviewBytes + 1
				case "oversize-stream":
					resp.ContentLength = -1
					resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(fixturePreview), io.LimitReader(zeroMediaReader{}, MaxPreviewBytes)))
				case "bad-mime":
					resp.Header.Set("Content-Type", "text/html")
				case "bad-container":
					resp.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 20)))
				case "forbidden-redirect":
					resp.StatusCode = 302
					resp.Header.Set("Location", "https://evil.test/file.m4a?secret=x")
				case "cancelled":
					cancel()
				case "destination-race":
					if err := os.WriteFile(dest, []byte("existing"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return resp, nil
			})}
			_, err := DownloadPreview(ctx, hc, Preview{URL: fixturePreviewURL}, dest)
			if err == nil {
				t.Fatal("accepted invalid transfer")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "evil.test") {
				t.Fatal("sensitive transport details in error")
			}
			entries, _ := os.ReadDir(dir)
			if scenario == "destination-race" {
				b, _ := os.ReadFile(dest)
				if string(b) != "existing" || len(entries) != 1 {
					t.Fatal("overwrote racing file")
				}
			} else if len(entries) != 0 {
				t.Fatal("failed transfer left files")
			}
			if calls != 1 {
				t.Fatal("followed forbidden redirect")
			}
		})
	}
}

type mediaBrokenReader struct{}

func (mediaBrokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestPreviewRejectsUntrustedLocations(t *testing.T) {
	hc := &http.Client{Transport: mediaRoundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("untrusted URL made request"); return nil, nil })}
	for _, location := range []string{"http://audio.mzstatic.com/file", "https://mzstatic.com.evil.test/file", "https://audio.mzstatic.com:444/file", "https://user:pass@audio.mzstatic.com/file", "https://audio.mzstatic.com/file#fragment", "https://audio.mzstatic.com/file.m3u8"} {
		if _, err := DownloadPreview(context.Background(), hc, Preview{URL: location}, filepath.Join(t.TempDir(), "file")); err == nil {
			t.Fatal("accepted untrusted preview URL")
		}
	}
}

func TestFetchHLSOnlyFetchesManifest(t *testing.T) {
	calls := 0
	hc := &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			t.Fatal("fetched a key or segment")
		}
		return mediaResponse(r, 200, "#EXTM3U\n#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"skd://secret-key\",KEYFORMAT=\"com.apple.streamingkeydelivery\"\n#EXTINF:2,\nsegment.mp4\n#EXT-X-ENDLIST\n"), nil
	})}
	m, err := FetchHLS(context.Background(), hc, "https://audio.mzstatic.com/test.m3u8")
	if err != nil || !m.EncryptionSignaled || calls != 1 {
		t.Fatal("wrong manifest fetch behavior", err)
	}
}

func TestFetchHLSValidatesCompleteTransferBeforeParsing(t *testing.T) {
	const playlist = "#EXTM3U\n#EXTINF:2,\nsegment.mp4\n#EXT-X-ENDLIST\n"
	const broken = "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=256000,CODECS=\""
	for _, scenario := range []string{"length", "partial-valid", "partial-quote", "oversize-header", "oversize-stream", "cancelled", "complete-invalid"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := "HLS transfer incomplete"
			hc := &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				resp := mediaResponse(r, 200, playlist)
				switch scenario {
				case "length":
					resp.ContentLength++
				case "partial-valid", "partial-quote":
					prefix := playlist
					if scenario == "partial-quote" {
						prefix = broken
					}
					resp.ContentLength = -1
					resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(prefix), mediaBrokenReader{}))
				case "oversize-header":
					resp.ContentLength = maxResponseBytes + 1
					want = "HLS playlist exceeds size limit"
				case "oversize-stream":
					resp.ContentLength = -1
					resp.Body = io.NopCloser(io.LimitReader(zeroMediaReader{}, maxResponseBytes+1))
					want = "HLS playlist exceeds size limit"
				case "cancelled":
					cancel()
				case "complete-invalid":
					resp = mediaResponse(r, 200, broken)
					want = "unterminated HLS attribute"
				}
				return resp, nil
			})}
			m, err := FetchHLS(ctx, hc, "https://audio.mzstatic.com/test.m3u8?signature=private")
			if scenario == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v, want cancellation", err)
				}
			} else if err == nil || err.Error() != want {
				t.Fatalf("got %v, want %s", err, want)
			}
			if m != nil {
				t.Fatal("returned a manifest for a failed transfer")
			}
		})
	}
}

func TestHLSAODRedirectAndCookieIsolation(t *testing.T) {
	const playlistURL = "https://aod.itunes.apple.com/fixture/playlist.m3u8?fixture=secret"
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(playlistURL)
	jar.SetCookies(u, []*http.Cookie{{Name: "account", Value: "secret"}})
	calls := 0
	hc := &http.Client{Jar: jar, Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Fatal("playlist request included account headers")
		}
		if calls == 1 {
			resp := mediaResponse(r, 302, "")
			resp.Header.Set("Location", "https://audio.mzstatic.com/redirect/master.m3u8")
			return resp, nil
		}
		return mediaResponse(r, 200, "#EXTM3U\n#EXTINF:2,\nsegment.mp4\n#EXT-X-ENDLIST\n"), nil
	})}
	m, err := FetchHLS(context.Background(), hc, playlistURL)
	if err != nil || calls != 2 || m.Segments[0].URL != "https://audio.mzstatic.com/redirect/segment.mp4" {
		t.Fatal("AOD redirect or relative resolution failed", err)
	}
	if _, err := validateCDN(playlistURL); err == nil {
		t.Fatal("playlist exception expanded preview destinations")
	}
}

func TestHLSRejectsUnreviewedLocationsAndRedirects(t *testing.T) {
	for _, raw := range []string{
		"http://aod.itunes.apple.com/fixture/playlist.m3u8",
		"https://aod.itunes.apple.com.evil.test/fixture/playlist.m3u8",
		"https://aod.itunes.apple.com:443/fixture/playlist.m3u8",
		"https://user:secret@aod.itunes.apple.com/fixture/playlist.m3u8",
		"https://aod.itunes.apple.com/fixture/playlist.m3u8#secret",
		"https://aod.itunes.apple.com/fixture/segment.m4a",
		"https://play.itunes.apple.com/WebObjects/MZPlay.woa/music/fps",
		"https://play.itunes.apple.com/WebObjects/MZPlay.woa/hls/playlist.m3u8",
	} {
		calls := 0
		hc := &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			resp := mediaResponse(r, 302, "")
			resp.Header.Set("Location", raw)
			return resp, nil
		})}
		if _, err := FetchHLS(context.Background(), hc, raw); err == nil || calls != 0 {
			t.Fatal("unreviewed initial URL accepted")
		}
		_, err := FetchHLS(context.Background(), hc, "https://audio.mzstatic.com/master.m3u8")
		if err == nil || calls != 1 || strings.Contains(err.Error(), "secret") {
			t.Fatal("unreviewed redirect followed or leaked")
		}
	}
}
