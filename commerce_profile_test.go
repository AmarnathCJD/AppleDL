package applemusic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"howett.net/plist"
)

func reviewedBag(t *testing.T) map[string]any {
	t.Helper()
	var bag map[string]any
	if err := json.Unmarshal(reviewedCommercePolicy, &bag); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"authenticateAccount": CommerceAuthURL, "amd-finish-provisioning": CommerceAMDFinishURL, "sign-sap-setup-cert": SAPCertURL, "sign-sap-setup": SAPSetupURL, "sign-sap-version": "200", "storefront-header-suffix": " t:music31", "storeFrontId": "143441"} {
		bag[k] = v
	}
	return bag
}

func TestCommercePolicyChangesRequireReview(t *testing.T) {
	for _, change := range []string{"", "authenticateAccount", "sign-sap-request", "signed-actions", "fpdi-config", "amd-domains", "md-domains", "sign-sap-version", "storeFrontId"} {
		t.Run(change, func(t *testing.T) {
			bag := reviewedBag(t)
			if change != "" {
				bag[change] = "unreviewed"
			}
			raw, _ := json.Marshal(bag)
			profile, err := ParseCommerceProfile(raw)
			if (err == nil) != (change == "") {
				t.Fatal("unexpected policy result")
			}
			if err == nil {
				h, e := profile.Headers(DeviceMetadata{UserAgent: "test", Language: "en-US"})
				if e != nil || h.Get("X-Apple-Store-Front") != "143441 t:music31" {
					t.Fatal("invalid profile headers")
				}
			}
		})
	}
}

func TestCommerceAMDProvisioning(t *testing.T) {
	for _, mode := range []string{"success", "wrong action", "empty challenge", "duplicate challenge", "invalid base64", "cancel before", "start failure", "empty cpim", "http error", "bad field", "keybag", "finish failure", "close failure", "finish and close", "cancel response"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			starts, requests, finishes, closes := 0, 0, 0, 0
			var buffers [][]byte
			primary, cleanup := errors.New("primary"), errors.New("cleanup")
			h := http.Header{}
			h.Set("X-Apple-AMD-Action", "SP")
			h.Set("X-Apple-AMD-Data", "AQ==")
			switch mode {
			case "wrong action":
				h.Set("X-Apple-AMD-Action", "RP")
			case "empty challenge":
				h.Del("X-Apple-AMD-Data")
			case "duplicate challenge":
				h.Add("X-Apple-AMD-Action", "SP")
			case "invalid base64":
				h.Set("X-Apple-AMD-Data", "AQ==%%%")
			case "cancel before":
				cancel()
			}
			c, _ := New(Config{HTTPClient: &http.Client{Transport: commerceRoundTripper(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.Method != "POST" || r.URL.String() != CommerceAMDFinishURL || r.GetBody != nil || r.Header.Get("Content-Type") != commerceContentType {
					t.Error("wrong finish transport")
				}
				raw, _ := io.ReadAll(r.Body)
				var body map[string]any
				if _, err := plist.Unmarshal(raw, &body); err != nil || len(body) != 2 || body["clientData"] != "Ag==" || body["guid"] != "test-guid" {
					t.Error("wrong finish body or wire types")
				}
				fields := map[string]any{"settingInfo": "Aw==", "transportKey": "BA=="}
				if mode == "bad field" {
					fields["settingInfo"] = []byte{3}
				}
				if mode == "keybag" {
					fields["keybag"] = []byte{5}
				}
				if mode == "cancel response" {
					cancel()
				}
				status := 200
				if mode == "http error" {
					status = 401
				}
				encoded, _ := plist.Marshal(fields, plist.XMLFormat)
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(encoded))}, nil
			})}})
			native := func(ctx context.Context, dsid int64, spim []byte) ([]byte, NativeProvisioningSession, error) {
				starts++
				if dsid != -1 || !bytes.Equal(spim, []byte{1}) {
					t.Error("wrong native start")
				}
				cpim := []byte{2}
				if mode == "empty cpim" {
					cpim = nil
				}
				buffers = append(buffers, spim, cpim)
				s := &testProvisioningSession{finish: func(ctx context.Context, ptm, tk []byte) error {
					finishes++
					if !bytes.Equal(ptm, []byte{3}) || !bytes.Equal(tk, []byte{4}) {
						t.Error("wrong native finish order/decoding")
					}
					buffers = append(buffers, ptm, tk)
					if mode == "finish failure" || mode == "finish and close" {
						return primary
					}
					return nil
				}, close: func() error {
					closes++
					if mode == "close failure" || mode == "finish and close" {
						return cleanup
					}
					return nil
				}}
				if mode == "start failure" {
					return cpim, s, primary
				}
				return cpim, s, nil
			}
			err := c.ProvisionCommerceAMD(ctx, &CommerceProfile{storefront: "143441 t:music31"}, "test-guid", nil, h, native)
			if (err == nil) != (mode == "success") {
				t.Fatalf("unexpected result: %v", err)
			}
			wantStarts, wantRequests, wantFinishes := 1, 1, 1
			switch mode {
			case "wrong action", "empty challenge", "duplicate challenge", "invalid base64", "cancel before":
				wantStarts, wantRequests, wantFinishes = 0, 0, 0
			case "start failure", "empty cpim":
				wantRequests, wantFinishes = 0, 0
			case "http error", "bad field", "keybag", "cancel response":
				wantFinishes = 0
			}
			if starts != wantStarts || requests != wantRequests || finishes != wantFinishes || closes != wantStarts {
				t.Fatalf("unexpected lifecycle: %d %d %d %d", starts, requests, finishes, closes)
			}
			if mode == "finish and close" && (!errors.Is(err, primary) || !errors.Is(err, cleanup)) {
				t.Error("lost cleanup or primary error")
			}
			if strings.HasPrefix(mode, "cancel") && !errors.Is(err, context.Canceled) {
				t.Error("lost cancellation")
			}
			for _, b := range buffers {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Error("owned buffer not cleared")
				}
			}
		})
	}
}
