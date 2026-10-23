package applemusic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func tokenFixture(t *testing.T) (*MediaTokenProfile, *MediaTokenSession) {
	t.Helper()
	bag := reviewedBag(t)
	bag["sf-api-token-service-url"] = MediaTokenURL
	raw, _ := json.Marshal(bag)
	p, err := ParseMediaTokenProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := &CommerceResponse{HTTPStatus: 200, HTTPHeaders: make(http.Header), Fields: map[string]any{
		"accountInfo": map[string]any{"appleId": "fixture@example.test"},
		"dsPersonId":  "123", "altDsid": "fixture-alt", "passwordToken": "fixture-commerce-secret",
	}}
	r.HTTPHeaders.Set("X-Set-Apple-Store-Front", "143441-1,32")
	r.HTTPHeaders.Add("Set-Cookie", "media=fixture-cookie; Domain=.itunes.apple.com; Path=/; Secure; Max-Age=3600")
	s, err := NewMediaTokenSession(r, time.Now().Add(-time.Minute))
	r.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Destroy)
	return p, s
}

func fixtureTokenPreparer(_ context.Context, r MediaTokenRequest) (http.Header, error) {
	h := r.Headers.Clone()
	h.Set("X-Apple-AMD", "fixture-otp")
	h.Set("X-Apple-AMD-M", "fixture-machine")
	h.Set("X-Apple-ActionSignature", "fixture-signature")
	return h, nil
}

func TestMediaTokenRequestAndSigning(t *testing.T) {
	p, s := tokenFixture(t)
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(MediaTokenURL)
	jar.SetCookies(u, []*http.Cookie{{Name: "implicit", Value: "secret"}})
	calls, preparations := 0, 0
	start := time.Now().UTC().Truncate(time.Second)
	c, err := New(Config{Headers: http.Header{"Authorization": {"secret"}, "X-Other-Identity": {"secret"}}, HTTPClient: &http.Client{Jar: jar, Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != mediaTokenRequestURL || r.Method != "GET" || r.Body != nil {
			t.Fatal("wrong media-token wire request")
		}
		if r.Header.Get("Cookie") != "media=fixture-cookie" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Other-Identity") != "" || r.Header.Get("iCloud-DSID") != "" {
			t.Fatal("request identity or cookie isolation failed")
		}
		if r.Header.Get("X-Apple-Store-Front") != "143441-1,32 t:music31" || r.Header.Get("X-Apple-ADSID") != "fixture-alt" || r.Header.Get("User-Agent") != "fixture-ua" || r.Header.Get("Accept-Language") != "en-US" {
			t.Fatal("wrong account decoration")
		}
		return mediaResponse(r, 200, `{"token":"fixture-media-token"}`), nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(ctx context.Context, req MediaTokenRequest) (http.Header, error) {
		preparations++
		h, _ := fixtureTokenPreparer(ctx, req)
		req.Headers = h
		data, err := MediaTokenSigningData(req)
		stamp := h.Get("X-Request-Timestamp")
		parsed, parseErr := time.Parse("2006-01-02T15:04:05Z", stamp)
		if parseErr != nil || parsed.Before(start) || parsed.After(time.Now().UTC()) {
			t.Fatal("wrong UTC timestamp")
		}
		want := "143441-1,32 t:music31musicAndroid" + stamp + "fixture-machine123musicAndroid"
		if err != nil || string(data) != want {
			t.Fatal("wrong signature byte order")
		}
		return h, nil
	}
	r, err := c.FetchMediaToken(context.Background(), p, s, DeviceMetadata{UserAgent: "fixture-ua", Language: "en-US"}, prepare)
	if err != nil || r.Token != "fixture-media-token" || r.ObtainedAt.IsZero() || calls != 1 || preparations != 1 {
		t.Fatal("media-token exchange failed")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", r, r), r.Token) {
		t.Fatal("token formatting exposed secret")
	}
	r.Destroy()
	if r.Token != "" {
		t.Fatal("destroy retained token")
	}
}

func TestMediaTokenCookieScopeAndLifetime(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cookies []string
		want    string
		fail    bool
	}{
		{"scope", []string{
			"a=1; Domain=.itunes.apple.com; Path=/; Secure",
			"host=secret; Path=/", "other=secret; Domain=evil.test; Path=/",
			"suffix=secret; Domain=.com; Path=/", "path=secret; Domain=.itunes.apple.com; Path=/auth",
		}, "a=1", false},
		{"original max age", []string{"old=secret; Domain=.itunes.apple.com; Path=/; Max-Age=10"}, "", false},
		{"live max age beats expires", []string{"a=1; Domain=.itunes.apple.com; Path=/; Max-Age=3600; Expires=Wed, 01 Jan 2020 00:00:00 GMT"}, "a=1", false},
		{"default path", []string{"a=secret; Domain=.itunes.apple.com"}, "", false},
		{"deletion order", []string{"a=1; Domain=.itunes.apple.com; Path=/", "a=deleted; Domain=.itunes.apple.com; Path=/; Max-Age=0"}, "", false},
		{"replacement", []string{"a=deleted; Domain=.itunes.apple.com; Path=/; Max-Age=0", "a=2; Domain=.itunes.apple.com; Path=/"}, "a=2", false},
		{"duplicate scope", []string{"a=1; Domain=.itunes.apple.com; Path=/", "a=2; Domain=.apple.com; Path=/"}, "", true},
		{"duplicate path", []string{"a=1; Domain=.itunes.apple.com; Path=/", "a=2; Domain=.itunes.apple.com; Path=/apiToken"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := make(http.Header)
			for _, c := range tc.cookies {
				h.Add("Set-Cookie", c)
			}
			s := &MediaTokenSession{cookies: (&http.Response{Header: h}).Cookies(), obtainedAt: time.Now().Add(-time.Minute)}
			got, err := s.cookieHeader(time.Now())
			if (err != nil) != tc.fail || got != tc.want {
				t.Fatal("unexpected cookie scope, lifetime or ambiguity handling")
			}
		})
	}
	s := &MediaTokenSession{obtainedAt: time.Now().Add(time.Hour)}
	if _, err := s.cookieHeader(time.Now()); err == nil {
		t.Fatal("future receipt accepted")
	}
}

func TestMediaTokenRejectsPreparerChanges(t *testing.T) {
	for _, mode := range []string{"identity", "remove", "extra", "duplicate", "alias", "missing signature", "control", "failure"} {
		t.Run(mode, func(t *testing.T) {
			p, s := tokenFixture(t)
			calls := 0
			c, _ := New(Config{HTTPClient: &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return mediaResponse(r, 200, `{"token":"x"}`), nil
			})}})
			prepare := func(ctx context.Context, r MediaTokenRequest) (http.Header, error) {
				h, _ := fixtureTokenPreparer(ctx, r)
				switch mode {
				case "identity":
					h.Set("X-DSID", "456")
				case "remove":
					h.Del("Cookie")
				case "extra":
					h.Set("Authorization", "secret")
				case "duplicate":
					h.Add("X-Apple-AMD", "second")
				case "alias":
					h["x-dsid"] = []string{"456"}
				case "missing signature":
					h.Del("X-Apple-ActionSignature")
				case "control":
					h.Set("X-Apple-AMD", "bad\r\nheader")
				case "failure":
					return nil, errors.New("fixture failure")
				}
				return h, nil
			}
			_, err := c.FetchMediaToken(context.Background(), p, s, DeviceMetadata{UserAgent: "fixture", Language: "en"}, prepare)
			if err == nil || calls != 0 {
				t.Fatal("invalid preparer reached network")
			}
		})
	}
}

func TestMediaTokenResponseFailures(t *testing.T) {
	for _, mode := range []string{"plist", "large valid token", "empty", "null", "array", "missing", "wrong type", "space", "control", "oversized token", "oversized body", "http", "redirect", "challenge", "transport", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			p, s := tokenFixture(t)
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, _ := New(Config{HTTPClient: &http.Client{Transport: mediaRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				body, status := `{"token":"fixture-token"}`, 200
				switch mode {
				case "plist":
					raw, _ := plist.Marshal(map[string]any{"token": "fixture-token"}, plist.BinaryFormat)
					body = string(raw)
				case "large valid token":
					body = `{"token":"` + strings.Repeat("x", 8192) + `"}`
				case "empty":
					body = ""
				case "null":
					body = "null"
				case "array":
					body = "[]"
				case "missing":
					body = `{"error":"SECRET"}`
				case "wrong type":
					body = `{"token":123}`
				case "space":
					body = `{"token":"bad token"}`
				case "control":
					body = `{"token":"bad\u0000token"}`
				case "oversized token":
					body = `{"token":"` + strings.Repeat("x", 65537) + `"}`
				case "oversized body":
					body = strings.Repeat(" ", maxResponseBytes+1)
				case "http":
					status = 401
				case "redirect":
					status = 302
				case "challenge":
					status = 403
				case "transport":
					return nil, errors.New("SECRET")
				}
				r := mediaResponse(req, status, body)
				if mode == "redirect" {
					r.Header.Set("Location", "https://example.test/SECRET")
				}
				if mode == "challenge" {
					r.Header.Set("X-Apple-AMD-Action", "RP")
					r.Header.Set("X-Apple-AMD-Data", "SECRET")
				}
				return r, nil
			})}})
			if mode == "cancel" {
				cancel()
			}
			r, err := c.FetchMediaToken(ctx, p, s, DeviceMetadata{UserAgent: "fixture", Language: "en"}, fixtureTokenPreparer)
			defer r.Destroy()
			wantOK := mode == "plist" || mode == "large valid token"
			if (err == nil) != wantOK {
				t.Fatal("unexpected response classification")
			}
			if err != nil && strings.Contains(err.Error(), "SECRET") {
				t.Fatal("error exposed sensitive response")
			}
			if mode == "challenge" && !errors.Is(err, ErrMediaDeviceChallenge) {
				t.Fatal("lost challenge")
			}
			wantCalls := 1
			if mode == "cancel" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatal("unexpected retry or cancelled request")
			}
		})
	}
}

func TestMediaTokenProfileAndSigningRestrictions(t *testing.T) {
	bag := reviewedBag(t)
	for _, endpoint := range []string{MediaTokenURL, "https://example.test/apiToken", MediaTokenURL + "?extra=1", ""} {
		bag["sf-api-token-service-url"] = endpoint
		raw, _ := json.Marshal(bag)
		_, err := ParseMediaTokenProfile(raw)
		if (err == nil) != (endpoint == MediaTokenURL) {
			t.Fatal("token endpoint restriction failed")
		}
	}
	base := MediaTokenRequest{URL: mediaTokenRequestURL, Method: "GET", Headers: make(http.Header)}
	for k, v := range map[string]string{"X-Apple-Store-Front": "143441 t:music31", "X-Apple-Client-Application": "musicAndroid", "X-Request-Timestamp": "2026-10-23T03:00:00Z", "X-Apple-AMD-M": "machine", "X-DSID": "123"} {
		base.Headers.Set(k, v)
	}
	for _, mode := range []string{"valid", "url", "query", "method", "missing", "duplicate", "timestamp", "fraction", "dsid"} {
		r := base
		r.Headers = base.Headers.Clone()
		switch mode {
		case "url":
			r.URL = "https://example.test/apiToken"
		case "query":
			r.URL += "&other=1"
		case "method":
			r.Method = "POST"
		case "missing":
			r.Headers.Del("X-Apple-AMD-M")
		case "duplicate":
			r.Headers.Add("X-DSID", "456")
		case "timestamp":
			r.Headers.Set("X-Request-Timestamp", "2026-10-23T03:00:00+01:00")
		case "fraction":
			r.Headers.Set("X-Request-Timestamp", "2026-10-23T03:00:00.123Z")
		case "dsid":
			r.Headers.Set("X-DSID", "0")
		}
		_, err := MediaTokenSigningData(r)
		if (err == nil) != (mode == "valid") {
			t.Fatal("signing restriction failed", mode)
		}
	}
	if _, err := NewMediaTokenSession(nil, time.Now()); err == nil {
		t.Fatal("nil commerce response accepted")
	}
}
