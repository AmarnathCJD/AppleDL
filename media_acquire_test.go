package applemusic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMediaResourceRangeSemantics(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		status                int
		body, contentRange    string
		position, length, cap int64
		want                  string
	}{
		{"full", 200, "abcdef", "", 0, -1, 6, "abcdef"},
		{"range-extra-byte", 206, "cdef", "bytes 2-5/8", 2, 3, 4, "cde"},
		{"range-at-end", 206, "cde", "bytes 2-4/5", 2, 3, 3, "cde"},
		{"range-unknown-total", 206, "cdef", "bytes 2-5/*", 2, 3, 4, "cde"},
		{"open-range", 206, "cdef", "bytes 2-5/6", 2, -1, 4, "cdef"},
		{"ignored-range", 200, "abcdef", "", 2, 3, 6, "cde"},
		{"ignored-open-range", 200, "abcdef", "", 2, -1, 6, "cdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hc := &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				want, _ := APKFileRange(tc.position, tc.length)
				if r.Header.Get("Range") != want {
					t.Fatal("incorrect APK range")
				}
				resp := mediaResponse(r, tc.status, tc.body)
				resp.Header.Set("Content-Range", tc.contentRange)
				return resp, nil
			})}
			got, err := FetchMediaResource(context.Background(), hc, fixturePreviewURL, FileRequestOptions{Position: tc.position, Length: tc.length}, tc.cap)
			if err != nil || string(got) != tc.want {
				t.Fatalf("resource mismatch: %q %v", got, err)
			}
		})
	}
}

func TestMediaResourceAODPolicy(t *testing.T) {
	const trusted = "https://aod.itunes.apple.com/fixture/full.mp4?private-token"
	for _, raw := range []string{
		"http://aod.itunes.apple.com/full.mp4", "https://aod.itunes.apple.com:443/full.mp4",
		"https://aod.itunes.apple.com.evil.test/full.mp4", "https://user:pass@aod.itunes.apple.com/full.mp4",
		"https://aod.itunes.apple.com/full.mp4#private", "https://aod.itunes.apple.com/playlist.m3u8",
		"https://play.itunes.apple.com/music/fps",
	} {
		calls := 0
		hc := &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			resp := mediaResponse(r, 302, "")
			resp.Header.Set("Location", raw)
			return resp, nil
		})}
		if _, err := FetchMediaResource(context.Background(), hc, raw, FileRequestOptions{Length: -1}, 10); err == nil || calls != 0 {
			t.Fatal("untrusted initial request")
		}
		if _, err := FetchMediaResource(context.Background(), hc, trusted, FileRequestOptions{Length: -1}, 10); err == nil || calls != 1 || strings.Contains(err.Error(), "private") {
			t.Fatal("untrusted redirect or leaked error")
		}
	}
	if err := validateMediaResourceLocation(trusted); err != nil {
		t.Fatal(err)
	}
	if _, err := validateCDN(trusted); err == nil {
		t.Fatal("resource exception expanded preview policy")
	}
}

func TestMediaResourceRejectsInvalidResponses(t *testing.T) {
	for _, scenario := range []string{"unsolicited-partial", "wrong-start", "too-long-range", "short-range", "bad-total", "missing-range", "wrong-length", "truncated-body", "oversized", "oversized-stream", "empty", "gzip", "status", "open-range-incomplete", "open-range-unknown", "skip-budget", "cancelled", "transport", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			options := FileRequestOptions{Position: 2, Length: 3}
			calls := 0
			hc := &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				resp := mediaResponse(r, 206, "cdef")
				resp.Header.Set("Content-Range", "bytes 2-5/8")
				switch scenario {
				case "unsolicited-partial":
					resp.Header.Set("Content-Range", "bytes 0-3/8")
				case "wrong-start":
					resp.Header.Set("Content-Range", "bytes 1-4/8")
				case "too-long-range":
					resp.Header.Set("Content-Range", "bytes 2-6/8")
					resp.ContentLength = 5
				case "short-range":
					resp.Header.Set("Content-Range", "bytes 2-3/8")
					resp.ContentLength = 2
				case "bad-total":
					resp.Header.Set("Content-Range", "bytes 2-5/5")
				case "missing-range":
					resp.Header.Del("Content-Range")
				case "wrong-length":
					resp.ContentLength = 3
				case "truncated-body":
					resp.Body = io.NopCloser(strings.NewReader("c"))
				case "oversized":
					resp.StatusCode = 200
					resp.ContentLength = 8
				case "oversized-stream":
					resp.StatusCode = 200
					resp.ContentLength = -1
					resp.Body = io.NopCloser(strings.NewReader("12345678"))
				case "empty":
					resp.StatusCode = 200
					resp.ContentLength = 0
					resp.Body = io.NopCloser(strings.NewReader(""))
				case "gzip":
					resp.Header.Set("Content-Encoding", "gzip")
				case "status":
					resp.StatusCode = 403
				case "open-range-unknown":
					resp.Header.Set("Content-Range", "bytes 2-5/*")
				case "skip-budget":
					resp.StatusCode = 200
				case "cancelled":
					cancel()
				case "transport":
					return nil, errors.New("private-server-secret")
				case "redirect":
					resp.StatusCode = 302
					resp.Header.Set("Location", "https://evil.test/private-server-secret")
				}
				return resp, nil
			})}
			switch scenario {
			case "unsolicited-partial", "oversized", "oversized-stream", "empty":
				options = FileRequestOptions{Length: -1}
			case "open-range-incomplete", "open-range-unknown":
				options.Length = -1
			case "skip-budget":
				options.Position = 4
			}
			_, err := FetchMediaResource(ctx, hc, fixturePreviewURL+"?private-server-secret", options, 6)
			if err == nil || strings.Contains(err.Error(), "private-server-secret") || calls != 1 {
				t.Fatal("invalid response accepted, retried or leaked", err)
			}
			if scenario == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation")
			}
		})
	}
}

func TestMediaResourceHeadersIsolatedAcrossRedirect(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(fixturePreviewURL)
	jar.SetCookies(u, []*http.Cookie{{Name: "account", Value: "secret"}})
	calls := 0
	hc := &http.Client{Jar: jar, Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		for _, key := range []string{"Cookie", "Authorization", "X-Dsid", "X-Apple-ActionSignature"} {
			if r.Header.Get(key) != "" {
				t.Fatal("account credential sent")
			}
		}
		if r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("User-Agent") != "fixture-player" || r.Header.Get("Accept-Language") != "en-US" || r.Header.Get("X-Playback-Session-Id") != "fixture-session" {
			t.Fatal("file headers lost")
		}
		resp := mediaResponse(r, 200, "abc")
		if calls == 1 {
			resp.StatusCode = 302
			resp.Header.Set("Location", "https://audio-ssl.itunes.apple.com/file")
		}
		return resp, nil
	})}
	_, err := FetchMediaResource(context.Background(), hc, fixturePreviewURL, FileRequestOptions{Length: -1, UserAgent: "fixture-player", Language: "en-US", PlaybackSessionID: "fixture-session"}, 6)
	if err != nil || calls != 2 {
		t.Fatal("redirect failed", err)
	}
}

const acquisitionFixture = `#EXTM3U
#EXT-X-MEDIA-SEQUENCE:9
#EXT-X-KEY:METHOD=SAMPLE-AES,URI="skd://private-key",KEYFORMAT="com.apple.streamingkeydelivery"
#EXT-X-MAP:URI="init.mp4"
#EXTINF:2.5,
one.mp4
#EXTINF:3,
two.mp4
#EXT-X-ENDLIST
`

func acquisitionManifest(t *testing.T) *HLSManifest {
	t.Helper()
	m, err := ParseHLS(strings.NewReader(acquisitionFixture), "https://audio.mzstatic.com/master.m3u8?private-token")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAcquireHLSCompleteOrderReceiptAndNoOverwrite(t *testing.T) {
	m := acquisitionManifest(t)
	var calls []string
	hc := &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.Path)
		return mediaResponse(r, 200, "data"), nil
	})}
	dest := filepath.Join(t.TempDir(), "song")
	got, err := AcquireHLS(context.Background(), hc, m, dest, HLSAcquisitionOptions{MaxBytes: 12})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"/init.mp4", "/one.mp4", "/two.mp4"}) {
		t.Fatal("wrong resource order or key fetched")
	}
	if got.TotalBytes != 12 || got.DurationSeconds != 5.5 || got.SegmentCount != 2 || !got.EncryptionSignaled || got.Decrypted || len(got.Files) != 3 {
		t.Fatal("wrong receipt")
	}
	for _, f := range got.Files {
		b, e := os.ReadFile(filepath.Join(dest, f.Name))
		if e != nil || string(b) != "data" || len(f.SHA256) != 64 {
			t.Fatal("saved file mismatch")
		}
	}
	b, err := os.ReadFile(filepath.Join(dest, "complete.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "private") || strings.Contains(string(b), "https") || strings.Contains(string(b), "skd:") {
		t.Fatal("receipt leaked network or key data")
	}
	var disk HLSAcquisitionReceipt
	if json.Unmarshal(b, &disk) != nil || !reflect.DeepEqual(*got, disk) {
		t.Fatal("receipt roundtrip")
	}
	if _, err = AcquireHLS(context.Background(), hc, m, dest, HLSAcquisitionOptions{}); err == nil || len(calls) != 3 {
		t.Fatal("overwrote destination")
	}
}

func TestAcquireHLSPreflightAndPartialFailure(t *testing.T) {
	for _, scenario := range []string{"gap", "unknown-tag", "untrusted-host", "bad-map", "bad-key", "bad-range", "live-playlist", "cancelled", "network-failure", "budget"} {
		t.Run(scenario, func(t *testing.T) {
			m := acquisitionManifest(t)
			dest := filepath.Join(t.TempDir(), "song")
			options := HLSAcquisitionOptions{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "gap":
				m.Segments[1].Gap = true
			case "unknown-tag":
				m.UnhandledTags = []string{"#EXT-X-UNKNOWN"}
			case "untrusted-host":
				m.Segments[1].URL = "https://evil.test/private"
			case "bad-map":
				i := 99
				m.Segments[1].MapIndex = &i
			case "bad-key":
				m.Segments[1].KeyIndices = []int{99}
			case "bad-range":
				m.Segments[1].ByteRange = "3@0"
			case "live-playlist":
				m.EndList = false
			case "cancelled":
				cancel()
			case "budget":
				options.MaxBytes = 5
			}
			calls := 0
			hc := &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if scenario == "network-failure" && calls == 2 {
					return nil, errors.New("private-url")
				}
				return mediaResponse(r, 200, "data"), nil
			})}
			result, err := AcquireHLS(ctx, hc, m, dest, options)
			if err == nil || result != nil || strings.Contains(err.Error(), "private") {
				t.Fatal("failure not redacted or reported")
			}
			if scenario == "network-failure" || scenario == "budget" {
				files, e := os.ReadDir(dest)
				if e != nil || len(files) != 1 || files[0].Name() != "init-0000.bin" || calls != 2 {
					t.Fatal("partial acquisition state wrong")
				}
			} else if _, e := os.Lstat(dest); !os.IsNotExist(e) || calls != 0 {
				t.Fatal("preflight caused side effects")
			}
		})
	}
}
