package applemusic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func playbackBagFixture(t *testing.T) map[string]any {
	t.Helper()
	bag := reviewedBag(t)
	var extra map[string]any
	if err := json.Unmarshal(reviewedPlaybackPolicy, &extra); err != nil {
		t.Fatal(err)
	}
	for key, value := range extra {
		if key == "musicMescal" {
			bag["musicCommon"] = map[string]any{key: value}
		} else {
			bag[key] = value
		}
	}
	return bag
}

func TestPlaybackPolicyRejectsChangedRules(t *testing.T) {
	for _, key := range []string{"enhanced-audio", "fps-cert", "externalAppIntegrity", "account-flow-url-patterns", "musicCommon", "fpdi-config", "signed-actions", "sign-sap-request"} {
		bag := playbackBagFixture(t)
		raw, _ := json.Marshal(bag)
		if _, err := ParsePlaybackProfile(raw); err != nil {
			t.Fatal(err)
		}
		bag[key] = nil
		raw, _ = json.Marshal(bag)
		if _, err := ParsePlaybackProfile(raw); err == nil {
			t.Fatalf("accepted changed %s", key)
		}
	}
}

func TestPlaybackTokenPreference(t *testing.T) {
	for _, tc := range []struct {
		token any
		want  string
		fail  bool
	}{
		{nil, "fallback", false}, {123, "fallback", false}, {"preferred", "preferred", false}, {"", "", true},
	} {
		r := &CommerceResponse{HTTPStatus: 200, HTTPHeaders: make(http.Header), Fields: map[string]any{
			"accountInfo": map[string]any{"appleId": "fixture@example.test"}, "dsPersonId": "123", "altDsid": "alt", "passwordToken": "fallback", "xToken": tc.token,
		}}
		r.HTTPHeaders.Set("X-Set-Apple-Store-Front", "143441-1,32")
		s, err := NewPlaybackSession(r, time.Now())
		if (err != nil) != tc.fail {
			t.Fatal("wrong account installation result")
		}
		if s != nil {
			if s.token != tc.want {
				t.Fatal("wrong token preference")
			}
			s.Destroy()
		}
	}
}

func TestPlaybackLicenseTransport(t *testing.T) {
	_, account := tokenFixture(t)
	account.cookies = append(account.cookies, &http.Cookie{Name: "fps", Value: "scoped", Domain: ".itunes.apple.com", Path: "/WebObjects/MZPlay.woa/music"}, &http.Cookie{Name: "wrong", Value: "secret", Domain: ".itunes.apple.com", Path: "/apiToken"})
	s := &PlaybackSession{account: account, token: "commerce-token"}
	bag, _ := json.Marshal(playbackBagFixture(t))
	p, err := ParsePlaybackProfile(bag)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{200, 302, 403} {
		calls, prepares := 0, 0
		c, err := New(Config{Headers: http.Header{"Authorization": {"global-secret"}}, HTTPClient: &http.Client{Transport: mediaRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.String() != PlaybackLicenseURL || r.Method != "POST" || r.Header.Get("X-Token") != "commerce-token" || r.Header.Get("Authorization") != "" {
				t.Fatal("wrong request identity")
			}
			if r.Header.Get("Cookie") != "fps=scoped; media=fixture-cookie" {
				t.Fatal("wrong URL cookie scope")
			}
			if r.Header.Get("X-Guid") != "0123456789abcdef" || r.Header.Get("X-Secure-Invalidation-Dsid") != "123" || r.Header.Get("X-Apple-Store-Front") != "143441-1,32 t:music31" {
				t.Fatal("wrong license headers")
			}
			body, _ := io.ReadAll(r.Body)
			var fields map[string]any
			if json.Unmarshal(body, &fields) != nil || fields["guid"] != "0123456789abcdef" || fields["spc"] != "AQID" || fields["offline"] != fmt.Sprint(calls == 2) {
				t.Fatal("wrong retry payload")
			}
			response := `{"status":-1004}`
			if calls == 2 {
				response = `{"ckc":"AQID","status":0,"version":1}`
			}
			return mediaResponse(r, code, response), nil
		})}})
		if err != nil {
			t.Fatal(err)
		}
		prepare := func(ctx context.Context, req PlaybackRequestPlan) (http.Header, error) {
			prepares++
			h := req.Headers.Clone()
			h.Set("X-Apple-AMD", fmt.Sprint(prepares))
			h.Set("X-Apple-AMD-M", "machine")
			clear(req.Body) // caller must not send a mutated preparation snapshot
			return h, nil
		}
		r, err := c.FetchPlaybackLicense(context.Background(), p, s, DeviceMetadata{StableID: "0123456789abcdef", UserAgent: "fixture-ua", Language: "en_US"}, LicenseRequest{Protocol: "simplified", GUID: "0123456789abcdef", AssetID: "1234", KeyURI: "skd://fixture", SPC: "AQID"}, prepare)
		if code == 200 {
			if err != nil || calls != 2 || prepares != 2 || !r.SentOffline || r.RequestedOffline {
				t.Fatal("license retry failed", err)
			}
			if strings.Contains(fmt.Sprintf("%v %#v", r, r), "AQID") {
				t.Fatal("license leaked in formatting")
			}
			r.Destroy()
		} else {
			var status *PlaybackHTTPError
			if !errors.As(err, &status) || status.StatusCode != code || calls != 1 {
				t.Fatal("lost HTTP status or retried failure")
			}
		}
	}
}
