package applemusic

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

type mediaRoundTripFunc func(*http.Request) (*http.Response, error)

func (f mediaRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func mediaResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r, ContentLength: int64(len(body))}
}
func fixtureMedia(t *testing.T, rt mediaRoundTripFunc) *MediaClient {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://amp-api.music.apple.com")
	jar.SetCookies(u, []*http.Cookie{{Name: "commerce", Value: "must-not-leak", Domain: ".music.apple.com", Path: "/"}})
	c, err := NewMedia(MediaConfig{HTTPClient: &http.Client{Transport: rt, Jar: jar}, BearerToken: "fixture-token", DSID: "123", UserAgent: "fixture-ua", Storefront: "us", Language: "en-US"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMediaSearchWireShapesAndRouting(t *testing.T) {
	for _, section := range []string{"song", "songs"} {
		t.Run(section, func(t *testing.T) {
			traits := `5`
			if section == "songs" {
				traits = `["atmos","lossless"]`
			}
			c := fixtureMedia(t, func(r *http.Request) (*http.Response, error) {
				q := r.URL.Query()
				if r.Method != "GET" || r.URL.Host != mediaSearchHost || r.URL.Path != "/v1/catalog/us/search" || q.Get("term") != "a & b + æ—¥æœ¬" || q.Get("types") != "songs" || q.Get("limit") != "4" || q.Get("offset") != "8" || q.Get("l") != "en-US" {
					t.Fatal("wrong search request")
				}
				if r.Header.Get("Authorization") != "Bearer fixture-token" || r.Header.Get("X-Dsid") != "123" || r.Header.Get("User-Agent") != "fixture-ua" || r.Header.Get("Cookie") != "" {
					t.Fatal("wrong media headers")
				}
				return mediaResponse(r, 200, `{"results":{"`+section+`":{"data":[{"id":"1","type":"songs","attributes":{"name":"Fixture","artistName":"Artist","isrc":"USAAA0000001","audioTraits":`+traits+`,"extendedAssetUrls":{"enhancedHls":"https://audio.mzstatic.com/master.m3u8"},"assetTokens":{"key":"secret"},"offers":{"subscription":{}},"previews":[{"url":"https://audio.mzstatic.com/preview.m4a"}]}}],"next":"/v1/catalog/us/search?offset=12"}}}`), nil
			})
			result, err := c.SearchSongs(context.Background(), "a & b + æ—¥æœ¬", SearchOptions{Limit: 4, Offset: 8})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Results.Songs.Data) != 1 || result.Results.Songs.Data[0].Attributes.ISRC != "USAAA0000001" || result.Results.Songs.Next == "" {
				t.Fatal("lost song metadata")
			}
			if string(result.Results.Songs.Data[0].Attributes.AudioTraits) != traits {
				t.Fatal("lost audio trait representation")
			}
		})
	}
}

func TestMediaDeviceChallenge(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized} {
		for _, value := range []string{"", "private-challenge-data"} {
			calls := 0
			c := fixtureMedia(t, func(r *http.Request) (*http.Response, error) {
				calls++
				resp := mediaResponse(r, status, `{"results":{}}`)
				resp.Header.Set("X-Apple-AMD-Action", value)
				resp.Header.Set("X-Apple-AMD-Data", value)
				return resp, nil
			})
			_, err := c.SearchSongs(context.Background(), "test", SearchOptions{})
			if !errors.Is(err, ErrMediaDeviceChallenge) || calls != 1 {
				t.Fatal("device challenge was accepted or retried")
			}
			if strings.Contains(err.Error(), "private-challenge-data") {
				t.Fatal("device challenge leaked")
			}
		}
	}
	for _, single := range []string{"X-Apple-AMD-Action", "X-Apple-AMD-Data"} {
		c := fixtureMedia(t, func(r *http.Request) (*http.Response, error) {
			resp := mediaResponse(r, http.StatusOK, `{"results":{}}`)
			resp.Header.Set(single, "private-challenge-data")
			return resp, nil
		})
		if _, err := c.SearchSongs(context.Background(), "test", SearchOptions{}); err != nil {
			t.Fatal("single header was treated as paired challenge")
		}
	}
}

func TestMediaSuggestions(t *testing.T) {
	const body = `{"results":{"suggestions":[{"kind":"terms","searchTerm":"Daft Punk"},{"kind":"topResults","content":{"id":"1","type":"artists"}}]}}`
	c := fixtureMedia(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != mediaSearchHost || r.URL.Path != "/v1/catalog/us/search/suggestions" || r.URL.Query().Get("term") != "Daft & friends" || r.URL.Query().Get("l") != "en-US" {
			t.Fatal("wrong suggestions request")
		}
		return mediaResponse(r, http.StatusOK, body), nil
	})
	result, err := c.Suggestions(context.Background(), "Daft & friends")
	if err != nil || string(result) != body {
		t.Fatal("heterogeneous suggestions response was lost")
	}
}

func TestMediaCatalogAndWebAssets(t *testing.T) {
	calls := 0
	c := fixtureMedia(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != mediaCatalogHost {
			t.Fatal("wrong catalog host")
		}
		q := r.URL.Query()
		switch r.URL.Path {
		case "/v1/catalog/us/songs":
			if q.Get("ids") != "1,2" || q.Get("include") != "albums,artists" || q.Get("extend") != "extendedAssetUrls,offers" {
				t.Fatal("wrong song query")
			}
			return mediaResponse(r, 200, `{"data":[]}`), nil
		case "/v1/play/assets":
			if q.Get("id") != "library.id+1" || q.Get("kind") != "song" || q.Get("hlsEncryption") != "CBC" || q.Get("hlsProfile") != "enhancedHls" {
				t.Fatal("wrong asset query")
			}
			return mediaResponse(r, 200, `{"results":{"assets":[{"url":"https://audio.mzstatic.com/master.m3u8?sig=x","bitRate":256000}]}}`), nil
		default:
			t.Fatal("unexpected request")
			return nil, nil
		}
	})
	if _, err := c.Songs(context.Background(), []string{"1", "2"}, SongOptions{Include: []string{"albums", "artists"}, ExtendedAssets: true}); err != nil {
		t.Fatal(err)
	}
	a, err := c.PlayAssets(context.Background(), "library.id+1")
	if err != nil {
		t.Fatal(err)
	}
	d, err := a.Results.Assets[0].Describe()
	if err != nil || d.Transport != "hls" || d.Protection != "pastis-fmp4" || d.CertificateURL != "https://s.mzstatic.com/skdtool_2021_certbundle.bin" || d.KeyServerProtocol != "simplified" {
		t.Fatal("wrong asset description")
	}
	d, err = (PlayAsset{URL: "https://audio.mzstatic.com/full.m4p"}).Describe()
	if err != nil || d.Protection != "unknown" {
		t.Fatal("progressive asset assumed clear")
	}
	if calls != 2 {
		t.Fatal("unexpected requests")
	}
}

func TestMediaPaginationBoundary(t *testing.T) {
	calls := 0
	c := fixtureMedia(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/v1/catalog/us/search" {
			if r.URL.Host != mediaSearchHost {
				t.Fatal("relative search page lost search host")
			}
			return mediaResponse(r, 200, `{"results":{"song":{"data":[]}}}`), nil
		}
		return mediaResponse(r, 200, `{"data":[],"next":"/v1/catalog/us/songs?offset=2"}`), nil
	})
	for _, next := range []string{"/v1/catalog/us/search?offset=1", "https://amp-api.music.apple.com/v1/catalog/us/songs?offset=1"} {
		if _, err := c.NextSongs(context.Background(), next); err != nil {
			t.Fatal(err)
		}
	}
	for _, next := range []string{"https://evil.test/v1/catalog/us/songs", "//evil.test/v1/catalog/us/songs", "http://amp-api.music.apple.com/v1/catalog/us/songs", "https://amp-api.music.apple.com:443/v1/catalog/us/songs", "/v1/catalog/in/songs", "/v1/catalog/us/%2e%2e/me", "/v1/catalog/us/songs#x", "?offset=2"} {
		if _, err := c.NextSongs(context.Background(), next); err == nil {
			t.Fatal("accepted untrusted next URL")
		}
	}
	if calls != 2 {
		t.Fatal("untrusted pagination made a request")
	}
}

func TestMediaResponseErrorsAndRedirects(t *testing.T) {
	for _, body := range []string{"", "null", "[]", "{}", `{"data":[]}`, `{"results":null}`, `{"results":{"song":null}}`, `{"results":{"songs":{"data":[]},"song":{"data":[]}}}`, `{"results":{}} trailing`, `{"errors":[{"detail":"SECRET"}]}`, strings.Repeat(" ", maxResponseBytes+1)} {
		c := fixtureMedia(t, func(r *http.Request) (*http.Response, error) { return mediaResponse(r, 200, body), nil })
		_, err := c.SearchSongs(context.Background(), "test", SearchOptions{})
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatal("invalid or sensitive response handling")
		}
	}
	calls := 0
	c := fixtureMedia(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := mediaResponse(r, 302, "SECRET")
		resp.Header.Set("Location", "https://evil.test")
		return resp, nil
	})
	_, err := c.SearchSongs(context.Background(), "test", SearchOptions{})
	var he *MediaHTTPError
	if !errors.As(err, &he) || he.StatusCode != 302 || calls != 1 {
		t.Fatal("media redirected")
	}
	if _, err := NewMedia(MediaConfig{}); !errors.Is(err, ErrMediaTokenRequired) {
		t.Fatal("accepted missing token")
	}
}

func TestPublicCatalogIsSeparate(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://itunes.apple.com")
	jar.SetCookies(u, []*http.Cookie{{Name: "commerce", Value: "secret"}})
	calls := 0
	c := NewPublicCatalog(&http.Client{Jar: jar, Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "itunes.apple.com" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Dsid") != "" {
			t.Fatal("public credential isolation failed")
		}
		if r.URL.Query().Get("entity") != "song" || r.URL.Query().Get("country") != "us" {
			t.Fatal("wrong public query")
		}
		return mediaResponse(r, 200, `{"resultCount":1,"results":[{"kind":"song","trackId":1,"trackName":"Fixture"}]}`), nil
	})})
	if _, err := c.SearchSongs(context.Background(), "test", "us", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.LookupSongs(context.Background(), []string{"1"}, "us"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("wrong public request count")
	}
}
