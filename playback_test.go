package applemusic

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestPlaybackPayloadWireTypes(t *testing.T) {
	id := int64(123)
	p, err := NewLeasePayload("fixture-guid", LeaseStart, &id, []byte{0xff, 0x80})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	if string(b) != `{"guid":"fixture-guid","sbsync":"/4A=","action":"lease-start","salableAdamId":"123"}` {
		t.Fatalf("lease payload: %s", b)
	}
	p, _ = NewLeasePayload("", LeaseRenew, nil, nil)
	b, _ = json.Marshal(p)
	if string(b) != `{"action":"lease-renew"}` {
		t.Fatalf("optional fields: %s", b)
	}
	for action, want := range map[LeaseAction]int{LeaseStart: 308, LeaseDownload: 308, LeaseRenew: 310} {
		got, err := action.NativeTransaction()
		if err != nil || got != want {
			t.Fatalf("native transaction %s", action)
		}
	}
	if _, err := NewLeasePayload("", "stop", nil, nil); err == nil {
		t.Fatal("invalid action accepted")
	}
	r := LicenseRequest{Protocol: "SiMpLiFiEd", GUID: "g", AssetID: "123", KeyURI: "skd://fixture", SPC: "opaque"}
	b, err = r.Body()
	if err != nil || string(b) != `{"guid":"g","adamId":"123","offline":"false","keyUri":"skd://fixture","spc":"opaque"}` {
		t.Fatalf("simplified payload: %s, %v", b, err)
	}
	r.Protocol = "standard"
	b, err = r.Body()
	if err != nil || string(b) != `{"fairplay-streaming-request":{"streaming-keys":[{"id":"0","uri":"skd://fixture","spc":"opaque"}]}}` {
		t.Fatalf("standard payload: %s, %v", b, err)
	}
	r.Protocol = "other"
	if _, err := r.Body(); err == nil {
		t.Fatal("invalid protocol accepted")
	}
}

func TestLeaseXMLAndModelContract(t *testing.T) {
	xml := `<?xml version="1.0"?><plist version="1.0"><dict><key>songList</key><array><dict><key>songId</key><integer>123</integer><key>assets</key><array><dict><key>URL</key><string>https://example.invalid/song</string><key>flavor</key><string>LW</string><key>sinfs</key><array><dict><key>sinf</key><data>/4A=</data><key>sinf2</key><data>AAE=</data></dict></array></dict></array></dict></array></dict></plist>`
	r, err := ParseLeaseResponseXML([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.LeaseDurationInSeconds != 600 || r.Status == nil || *r.Status != 0 || r.HTTPStatusCode == nil || *r.HTTPStatusCode != -1 {
		t.Fatal("lease defaults lost")
	}
	if r.SongList[0].SongID != 123 || !reflect.DeepEqual(r.SongList[0].Assets[0].SINFs[0].SINF, SignedBytes{255, 128}) {
		t.Fatal("plist data bytes changed")
	}
	b, _ := json.Marshal(r.SongList[0].Assets[0].SINFs[0].SINF)
	if string(b) != "[-1,-128]" {
		t.Fatalf("signed normalization: %s", b)
	}
	binary, _ := plist.Marshal(map[string]any{}, plist.BinaryFormat)
	if _, err := ParseLeaseResponseXML(binary); err == nil {
		t.Fatal("binary plist accepted on XML path")
	}
	if _, err := ParseLeaseResponseXML([]byte(`{}`)); err == nil {
		t.Fatal("JSON accepted on XML path")
	}
	r, err = ParseLeaseResponseJSON([]byte(`{"failureType":0,"songList":[{"songId":1,"key-server-protocol-type":"standard","key-sever-protocol-type":"simplified","assets":[{"URL":null,"flavor":null}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var failure *LeaseFailure
	if !errors.As(r.CheckFailure(), &failure) || failure.Code != 0 {
		t.Fatal("failureType zero must fail")
	}
	if *r.SongList[0].KeyServerProtocol != "standard" || *r.SongList[0].KeySeverProtocol != "simplified" {
		t.Fatal("APK spelling aliases merged")
	}
	r, err = ParseLeaseResponseJSON([]byte(`{"songList":null,"status":null,"httpStatusCode":null,"LeaseDurationInSeconds":1}`))
	if err != nil || r.SongList != nil || r.Status != nil || r.HTTPStatusCode != nil || r.LeaseDurationInSeconds != 600 {
		t.Fatal("nullability or exact case changed")
	}
	for _, bad := range []string{
		`null`, `[]`, `{"leaseDurationInSeconds":null}`, `{"songList":[{}]}`, `{"songList":[{"songId":null}]}`,
		`{"songList":[{"songId":1,"assets":[{"url":"wrong-case","flavor":"LW"}]}]}`,
		`{"songList":[{"songId":1,"assets":[{"URL":null,"flavor":null,"sinfs":[{"sinf":[],"sinf2":[null]}]}]}]}`,
	} {
		if _, err := ParseLeaseResponseJSON([]byte(bad)); err == nil {
			t.Fatalf("invalid model accepted: %s", bad)
		}
	}
	for _, bad := range []string{`null`, `"/4A="`, `[128]`, `[-129]`, `[null]`, `[1.5]`} {
		var bytes SignedBytes
		if json.Unmarshal([]byte(bad), &bytes) == nil {
			t.Fatalf("invalid bytes accepted: %s", bad)
		}
	}
}

func TestLicenseResponseContracts(t *testing.T) {
	r, err := ParseLicenseResponse("simplified", []byte(`{"ckc":"opaque","renew-after":2}`), 1234)
	if err != nil || r.ExpiresAtMillis != 3234 || r.Version != 0 || r.Status != 0 {
		t.Fatalf("renewal: %+v %v", r, err)
	}
	r, err = ParseLicenseResponse("simplified", []byte(`{"ckc":"opaque","status":-99}`), 1234)
	if err != nil || r.ExpiresAtMillis != math.MaxInt64 || r.RenewAfter != -1 {
		t.Fatal("simplified defaults/status behavior")
	}
	r, err = ParseLicenseResponse("standard", []byte(`{"fairplay-streaming-response":{"streaming-keys":[{"ckc":"first"},{"ckc":"second"}]}}`), 1234)
	if err != nil || r.CKC != "first" || r.Status != -1 || r.ExpiresAtMillis != math.MaxInt64 {
		t.Fatal("standard first-key/default status behavior")
	}
	for _, bad := range []string{`{}`, `{"CKC":"wrong-case"}`, `{"ckc":null}`, `{"ckc":"opaque","status":null}`, `{"ckc":"opaque","renew-after":9223372036854775807}`} {
		if _, err := ParseLicenseResponse("simplified", []byte(bad), 1234); err == nil {
			t.Fatalf("bad simplified accepted: %s", bad)
		}
	}
	if _, err := ParseLicenseResponse("simplified", []byte(`{"ckc":"opaque","renew-after":1}`), math.MaxInt64); err == nil {
		t.Fatal("expiry overflow accepted")
	}
	for _, bad := range []string{`{}`, `{"fairplay-streaming-response":{"streaming-keys":[]}}`, `{"fairplay-streaming-response":{"streaming-keys":[{"ckc":""},{"ckc":"usable"}]}}`, `{"fairplay-streaming-response":{"streaming-keys":[{"ckc":"first"},null]}}`} {
		if _, err := ParseLicenseResponse("standard", []byte(bad), 0); err == nil {
			t.Fatalf("bad standard accepted: %s", bad)
		}
	}
}

func TestLicenseRetryAndCancellation(t *testing.T) {
	clock := func() int64 { return 500 }
	for _, offline := range []bool{false, true} {
		calls := 0
		r, err := ExchangeLicense(context.Background(), LicenseRequest{Protocol: "simplified", Offline: offline}, clock, func(_ context.Context, body []byte) ([]byte, error) {
			var fields map[string]any
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			want := "false"
			if offline != (calls == 1) {
				want = "true"
			}
			if fields["offline"] != want {
				t.Fatalf("retry changed wrong field/type: %v", fields)
			}
			calls++
			if calls == 1 {
				return []byte(`{"status":-1004}`), nil
			}
			return []byte(`{"ckc":"opaque"}`), nil
		})
		if err != nil || calls != 2 || r.RequestedOffline != offline || r.SentOffline == offline {
			t.Fatal("slot retry metadata/call count")
		}
	}
	calls := 0
	_, err := ExchangeLicense(context.Background(), LicenseRequest{Protocol: "simplified"}, clock, func(context.Context, []byte) ([]byte, error) { calls++; return []byte(`{"status":-1004}`), nil })
	if !errors.Is(err, ErrLicenseSlotExhausted) || calls != 2 {
		t.Fatal("slot retry unbounded")
	}
	calls = 0
	r, err := ExchangeLicense(context.Background(), LicenseRequest{Protocol: "standard"}, clock, func(context.Context, []byte) ([]byte, error) {
		calls++
		return []byte(`{"fairplay-streaming-response":{"streaming-keys":[{"ckc":"opaque","status":-1004}]}}`), nil
	})
	if err != nil || calls != 1 || r.Status != -1004 {
		t.Fatal("standard status must not trigger slot retry")
	}
	calls = 0
	_, err = ExchangeLicense(context.Background(), LicenseRequest{Protocol: "simplified"}, clock, func(context.Context, []byte) ([]byte, error) { calls++; return nil, errors.New("fixture-secret") })
	if err == nil || strings.Contains(err.Error(), "fixture-secret") || calls != 1 {
		t.Fatal("exchange errors retried or leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ExchangeLicense(ctx, LicenseRequest{}, clock, func(context.Context, []byte) ([]byte, error) { t.Fatal("called after cancellation"); return nil, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not preserved")
	}
	ctx, cancel = context.WithCancel(context.Background())
	_, err = ExchangeLicense(ctx, LicenseRequest{Protocol: "simplified"}, clock, func(context.Context, []byte) ([]byte, error) { cancel(); return nil, context.Canceled })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("in-flight cancellation not preserved")
	}
}

func TestPlaybackRequestHeaders(t *testing.T) {
	s := StoreHeaderValues{UserAgent: "fixture-app", Locale: "zh_CN", Storefront: "fixture-store", Cookie: "fixture-cookie", XToken: "fixture-token", DSID: 12}
	p, err := PlanCertificateRequest("https://example.invalid/cert", "g", s)
	if err != nil || p.Method != "GET" || p.Headers.Get("X-Guid") != "g" || p.Headers.Get("X-Token") != "fixture-token" || p.Headers.Get("Accept-Language") != "zh-Hans" || p.Headers.Get("Content-Type") != "" || !p.StorePreparationRequired {
		t.Fatal("certificate headers")
	}
	for locale, want := range map[string]string{"zh-CN": "zh-CN", "zh_TW": "zh-Hant", "zh_HK": "zh-Hant", "en_US": "en-US"} {
		if StoreAcceptLanguage(locale) != want {
			t.Fatalf("locale %s", locale)
		}
	}
	for _, tc := range []struct {
		active, signedOut int64
		want              string
	}{{12, 34, "12"}, {0, 34, "34"}, {-2, 34, "34"}, {0, 0, "0"}} {
		s.DSID = tc.active
		p, err = PlanLicenseRequest("https://example.invalid/license", s, tc.signedOut, LicenseRequest{Protocol: "standard", GUID: "g"})
		if err != nil || p.Headers.Get("X-Secure-Invalidation-Dsid") != tc.want || p.Headers.Get("Content-Type") != "application/json" || p.Method != "POST" {
			t.Fatal("license headers")
		}
	}
	p, err = PlanLeaseRequest("https://example.invalid/subDownload", s, LeasePayload{Action: LeaseStart})
	if err != nil || p.ConnectTimeout != 4*time.Second || p.ReadTimeout != 4*time.Second {
		t.Fatal("lease timeout")
	}
	p, err = PlanMiniSINFRequest("https://example.invalid/fetchSinfs", StoreHeaderValues{}, MiniSINFPayload{GUID: "g"})
	if err != nil || string(p.Body) != `{"guid":"g","flavors":[],"adamIds":[]}` || p.Headers.Get("X-Dsid") != "" {
		t.Fatal("mini-SINF empty-array/header contract")
	}
	mini, err := ParseMiniSINFResponse([]byte(`{"123":{"LW":"opaque"}}`))
	if err != nil || mini["123"]["LW"] != "opaque" {
		t.Fatal("mini-SINF map")
	}
	for _, bad := range []string{`null`, `{"123":null}`, `{"123":{"LW":null}}`, `{"123":{"LW":1}}`} {
		if _, err := ParseMiniSINFResponse([]byte(bad)); err == nil {
			t.Fatal("bad mini-SINF accepted")
		}
	}
	for _, endpoint := range []string{"http://example.invalid", "https://user@example.invalid", "https://example.invalid/#fragment"} {
		if _, err := PlanCertificateRequest(endpoint, "g", s); err == nil {
			t.Fatal("bad endpoint accepted")
		}
	}
	if _, err := PlanCertificateRequest("https://example.invalid", "g\r\nInjected: value", s); err == nil {
		t.Fatal("header injection accepted")
	}
}

func TestAPKFileRangesAndHeaderSeparation(t *testing.T) {
	for _, tc := range []struct {
		pos, len int64
		want     string
	}{{0, -1, ""}, {100, -1, "bytes=100-"}, {100, 20, "bytes=100-120"}, {0, 1, "bytes=0-1"}} {
		r, err := APKFileRange(tc.pos, tc.len)
		if err != nil || r != tc.want {
			t.Fatalf("APK range %d/%d: %s", tc.pos, tc.len, r)
		}
	}
	for _, tc := range [][2]int64{{-1, 5}, {0, -2}, {math.MaxInt64, 1}} {
		if _, err := APKFileRange(tc[0], tc[1]); err == nil {
			t.Fatal("invalid range accepted")
		}
	}
	p, err := PlanFileRequest("https://example.invalid/song", FileRequestOptions{Length: -1, UserAgent: "fixture-player", Language: "en-US", PlaybackSessionID: "fixture-session"})
	if err != nil || p.Headers.Get("Accept-Encoding") != "identity" || p.Headers.Get("X-Playback-Session-Id") != "fixture-session" || p.ConnectTimeout != 4*time.Second || p.ReadTimeout != 2*time.Second || p.StorePreparationRequired {
		t.Fatal("file transport plan")
	}
	for _, name := range []string{"Authorization", "Cookie", "X-Token", "X-Dsid", "X-Apple-Store-Front"} {
		if p.Headers.Get(name) != "" {
			t.Fatalf("commerce header on file plan: %s", name)
		}
	}
	p, err = PlanFileRequest("https://example.invalid/song", FileRequestOptions{Length: -1, AllowGzip: true})
	if err != nil || p.Headers.Get("Accept-Encoding") != "" {
		t.Fatal("gzip flag")
	}
}

func TestPreferredAudioFlavors(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    AudioFlavorOptions
		want []string
	}{
		{"wifi", AudioFlavorOptions{NetworkAllowed: true, WiFi: true, BitrateEstimate: -1}, []string{"LWHQ", "LW", "SLW", "HLS"}},
		{"cell", AudioFlavorOptions{NetworkAllowed: true, BitrateEstimate: -1}, []string{"LW", "SLW", "HLS"}},
		{"saver", AudioFlavorOptions{NetworkAllowed: true, DataSaver: true, BitrateEstimate: -1}, []string{"SLW", "LW", "LWHQ", "HLS"}},
		{"offline-unfiltered", AudioFlavorOptions{BitrateEstimate: 1}, []string{"LWHQ", "LW", "SLW", "HLS"}},
		{"forced-before-offline", AudioFlavorOptions{DebugBuild: true, ForceDataSaver: true, BitrateEstimate: 128}, []string{"SLW", "LW", "HLS"}},
		{"hq-before-saver", AudioFlavorOptions{NetworkAllowed: true, HighQualityCellular: true, DataSaver: true, BitrateEstimate: 320}, []string{"LWHQ", "LW", "SLW", "HLS"}},
		{"boundary", AudioFlavorOptions{NetworkAllowed: true, WiFi: true, BitrateEstimate: 128, HLSEnabled: true, HLSConfigurationValid: true}, []string{"HLS", "LW", "SLW"}},
		{"fallback", AudioFlavorOptions{NetworkAllowed: true, WiFi: true, BitrateEstimate: 1, HLSEnabled: true}, []string{"SLW", "HLS"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := PreferredAudioFlavors(tc.o); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
