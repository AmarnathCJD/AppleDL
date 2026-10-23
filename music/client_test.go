package music

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/internal/dirlock"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{SessionFile: filepath.Join(dir, "session.dat"), StateDir: filepath.Join(dir, "device"), HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("unexpected network request")
		return nil, errors.New("offline")
	})}}
}

func syntheticSession(t *testing.T, dir string) string {
	t.Helper()
	ctx := context.Background()
	d, err := standalone.Open(ctx, standalone.Config{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	a := &am.SRPExchangeResult{AccountData: map[string]json.RawMessage{"adsid": json.RawMessage(`"synthetic-alt"`)}, Response: map[string]json.RawMessage{"Status": json.RawMessage(`{"ec":0}`), "M2": json.RawMessage(`"proof"`), "spd": json.RawMessage(`"data"`)}}
	defer a.Destroy()
	if err := d.SaveIdMSAccount(ctx, "fixture@example.invalid", a); err != nil {
		t.Fatal(err)
	}
	r := &am.CommerceResponse{HTTPStatus: 200, HTTPHeaders: make(http.Header), Fields: map[string]any{"accountInfo": map[string]any{"appleId": "fixture@example.invalid"}, "dsPersonId": "123", "altDsid": "synthetic-alt", "passwordToken": "synthetic-token"}}
	r.HTTPHeaders.Set("X-Set-Apple-Store-Front", "143441-1,32")
	r.HTTPHeaders.Add("Set-Cookie", "media=synthetic; Domain=.itunes.apple.com; Path=/; Secure")
	defer r.Destroy()
	if err := d.SaveCommerceResponse(ctx, "fixture@example.invalid", r); err != nil {
		t.Fatal(err)
	}
	device, err := d.ExportSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(sessionEnvelope{Version: 1, Country: "in", Device: device})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestSavedSessionPrecedenceAndFailedImportPreservesState(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	encoded := syntheticSession(t, filepath.Join(t.TempDir(), "device"))
	if err := os.WriteFile(cfg.SessionFile, []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Username = "fixture@example.invalid"
	cfg.Password = "must-not-be-used"
	calls := 0
	cfg.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.String() != am.CommerceBagURL {
			t.Error("saved session triggered a login request")
		}
		return nil, errors.New("deliberately offline")
	})
	if c, err := New(ctx, cfg); err == nil {
		c.Close()
		t.Fatal("offline validation accepted")
	}
	if calls != 1 {
		t.Fatal("saved session was not selected")
	}
	before, err := os.ReadFile(cfg.SessionFile)
	if err != nil || string(before) != encoded {
		t.Fatal("failed constructor changed session file")
	}
	entries, err := os.ReadDir(filepath.Dir(cfg.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "import-") {
			t.Fatal("failed import leaked staging directory")
		}
	}
	// An explicit export takes priority over the valid file, even if invalid.
	cfg.Session = "invalid"
	calls = 0
	if c, err := New(ctx, cfg); err == nil {
		c.Close()
		t.Fatal("invalid explicit export ignored")
	}
	if calls != 0 {
		t.Fatal("invalid explicit session caused network activity")
	}
	// Empty construction supports later imports and preserves its state on failure.
	cfg2 := testConfig(t)
	cfg2.HTTPClient = cfg.HTTPClient
	c, err := New(ctx, cfg2)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	previous := c.cfg.Country
	if err := c.ImportSession(ctx, encoded); err == nil {
		t.Fatal("offline import accepted")
	}
	if c.cfg.Country != previous || c.state != nil {
		t.Fatal("failed import replaced client state")
	}
}

func TestClientCancellationCloseAndRedaction(t *testing.T) {
	c, err := New(context.Background(), testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExportSession(); !errors.Is(err, ErrSessionRequired) {
		t.Fatal("empty export accepted")
	}
	if err := c.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Search(ctx, "fixture"); !errors.Is(err, context.Canceled) {
		t.Fatal("queued cancellation ignored")
	}
	c.unlock()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err := c.Search(context.Background(), "fixture"); !errors.Is(err, ErrClosed) {
		t.Fatal("closed client accepted operation")
	}
	cfg := Config{Username: "synthetic-email", Password: "synthetic-password", Session: "synthetic-session"}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), "synthetic-") {
		t.Fatal("config formatting exposes credentials")
	}
}

func TestCatalogAndFormatSelection(t *testing.T) {
	cfg := testConfig(t)
	requests := 0
	cfg.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		var body string
		switch {
		case strings.HasSuffix(r.URL.Path, "/songs"):
			if !strings.Contains(r.URL.RawQuery, "extendedAssetUrls") {
				t.Error("extended assets missing")
			}
			body = `{"data":[{"id":"123","attributes":{"name":"Fixture","artistName":"Artist","durationInMillis":1234,"extendedAssetUrls":{"enhancedHls":"https://audio-ssl.itunes.apple.com/fixture.m3u8?secret=signed"},"assetTokens":{"secret":"token"}}}]}`
		case r.URL.Path == "/fixture.m3u8":
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("catalog credentials leaked to CDN")
			}
			body = "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=256000,CODECS=\"mp4a.40.2\"\naac.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=1000000,CODECS=\"alac\"\na.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=2000000,CODECS=\"alac\"\nb.m3u8\n"
		default:
			t.Error("unexpected catalog request")
			body = `{}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r, ContentLength: int64(len(body))}, nil
	})
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	media, err := am.NewMedia(am.MediaConfig{BearerToken: "synthetic-token", Storefront: "us", HTTPClient: cfg.HTTPClient})
	if err != nil {
		t.Fatal(err)
	}
	c.state = &clientState{media: media}
	defer func() { c.state = nil; c.Close() }()
	song, err := c.GetSong(context.Background(), "123")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || song.Name != "Fixture" || len(song.Formats) != 3 {
		t.Fatal("metadata or formats missing")
	}
	if strings.Contains(fmt.Sprintf("%+v", song), "secret") {
		t.Fatal("metadata exposed private assets")
	}
	if i, err := selectFormat(song.Formats, ""); err != nil || i != 2 {
		t.Fatal("best ALAC not selected")
	}
	if i, err := selectFormat(song.Formats, song.Formats[1].ID); err != nil || i != 1 {
		t.Fatal("explicit ALAC not selected")
	}
	if _, err := selectFormat(song.Formats, song.Formats[0].ID); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatal("unsupported codec accepted")
	}
	if _, err := selectFormat(song.Formats, "missing"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatal("missing format accepted")
	}
	if _, err := c.DownloadAndDecryptSong(context.Background(), "123", t.TempDir()); err == nil {
		t.Fatal("existing output accepted")
	}
	if requests != 2 {
		t.Fatal("invalid output caused network access")
	}
}

func TestFormatIDsIgnoreRotatingURLs(t *testing.T) {
	v := []am.HLSVariant{{URL: "https://example.invalid/a?token=first", Codecs: "alac", Bandwidth: 1000}, {URL: "https://example.invalid/b", Codecs: "alac", Bandwidth: 1000}}
	before := variantFormats(v)
	v[0].URL = "https://example.invalid/a?token=second"
	after := variantFormats(v)
	if before[0].ID != after[0].ID || before[0].ID == before[1].ID {
		t.Fatal("format IDs rotate or collide")
	}
}

func TestSessionLockOwnershipAndFailureRecovery(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	c, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if other, err := New(ctx, cfg); !errors.Is(err, dirlock.ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatalf("second client: %v", err)
	}
	if err := c.SaveSession(""); !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("save to owned path: %v", err)
	}
	otherPath := filepath.Join(filepath.Dir(cfg.SessionFile), "other.dat")
	if err := c.SaveSession(otherPath); !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("save to alternate path: %v", err)
	}
	if _, err := os.Stat(otherPath + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed alternate save retained its lock")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Session = "invalid"
	if failed, err := New(ctx, cfg); err == nil {
		_ = failed.Close()
		t.Fatal("invalid session accepted")
	}
	cfg.Session = ""
	reopened, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("constructor failure retained lock: %v", err)
	}
	defer reopened.Close()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := dirlock.Acquire(cfg.SessionFile + ".lock"); !errors.Is(err, dirlock.ErrBusy) {
		t.Fatal("old client released the new owner's lock")
	}
}
