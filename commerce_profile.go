package applemusic

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"regexp"

	"howett.net/plist"
)

const CommerceBagURL = "https://bag.itunes.apple.com/bag.xml?deviceClass=Android&format=json&os=Android&osVersion=1606&product=Music&productVersion=7.0.0&profile=AndroidMusic&ix=6&profileVersion=1"
const CommerceAuthURL = "https://auth.itunes.apple.com/auth/v1/native"
const CommerceAMDFinishURL = "https://auth.itunes.apple.com/auth/v1/otp/1.5/finish"
const SAPCertURL = "https://s.mzstatic.com/sap/setupCert.plist"
const SAPSetupURL = "https://fpinit.itunes.apple.com/v1/signSapSetup"

// The policies are a public-bag snapshot reviewed against the supplied APK.
// Until a general native policy matcher is ported, changes to ANY of these
// policies require review. This prevents silently skipping new FPDI/signing rules.
//
//go:embed commerce_policy.json
var reviewedCommercePolicy []byte

type CommerceProfile struct{ storefront string }

func (p *CommerceProfile) Headers(m DeviceMetadata) (http.Header, error) {
	if p == nil || p.storefront == "" || m.UserAgent == "" || m.Language == "" || !validMetadataText(m.UserAgent) || !validMetadataText(m.Language) {
		return nil, errors.New("invalid commerce profile or metadata")
	}
	return http.Header{"User-Agent": {m.UserAgent}, "Accept-Language": {m.Language}, "X-Apple-Store-Front": {p.storefront}}, nil
}

func (c *Client) FetchCommerceProfile(ctx context.Context, userAgent string) (*CommerceProfile, error) {
	if userAgent == "" || !validMetadataText(userAgent) {
		return nil, errors.New("invalid commerce user agent")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", CommerceBagURL, nil)
	if err != nil {
		return nil, errors.New("create commerce bag request failed")
	}
	req.Header.Set("User-Agent", userAgent)
	raw, _, err := c.send(req)
	if err != nil {
		return nil, err
	}
	return ParseCommerceProfile(raw)
}

// ParseCommerceProfile supports only the reviewed AndroidMusic / SAP-200 profile.
func ParseCommerceProfile(raw []byte) (*CommerceProfile, error) {
	invalid := errors.New("unsupported commerce bag profile; signing policy needs review")
	if len(raw) > maxResponseBytes {
		return nil, invalid
	}
	var bag, reviewed map[string]any
	if json.Unmarshal(raw, &bag) != nil || json.Unmarshal(reviewedCommercePolicy, &reviewed) != nil {
		return nil, invalid
	}
	for key, value := range reviewed {
		if !reflect.DeepEqual(bag[key], value) {
			return nil, invalid
		}
	}
	for key, want := range map[string]string{"authenticateAccount": CommerceAuthURL, "amd-finish-provisioning": CommerceAMDFinishURL, "sign-sap-setup-cert": SAPCertURL, "sign-sap-setup": SAPSetupURL, "sign-sap-version": "200", "storefront-header-suffix": " t:music31"} {
		if bag[key] != want {
			return nil, invalid
		}
	}
	storefront, ok := bag["storeFrontId"].(string)
	if !ok || !regexp.MustCompile(`^[0-9]{6}$`).MatchString(storefront) {
		return nil, invalid
	}
	return &CommerceProfile{storefront: storefront + " t:music31"}, nil
}

// ProvisionCommerceAMD handles only the explicit V1.5 SP challenge. Existing
// provisioning cannot be erased by this operation. Caller retries authentication
// at most once, with fresh OTP headers and a new body signature.
func (c *Client) ProvisionCommerceAMD(ctx context.Context, profile *CommerceProfile, guid string, headers http.Header, challenge http.Header, native NativeProvisioningStarter) (err error) {
	if profile == nil || profile.storefront == "" || native == nil || guid == "" || challenge.Get("X-Apple-AMD-Action") != "SP" {
		return errors.New("unsupported commerce device challenge")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded := challenge.Get("X-Apple-AMD-Data")
	if len(challenge.Values("X-Apple-AMD-Action")) != 1 || len(challenge.Values("X-Apple-AMD-Data")) != 1 || len(encoded) > base64.StdEncoding.EncodedLen(maxResponseBytes) {
		return errors.New("invalid commerce provisioning challenge")
	}
	spim, err := base64.StdEncoding.Strict().DecodeString(encoded)
	defer clear(spim)
	if err != nil || len(spim) == 0 || len(spim) > maxResponseBytes {
		return errors.New("invalid commerce provisioning challenge")
	}
	cpim, session, err := native(ctx, AnisetteV15DSID, spim)
	defer clear(cpim)
	if session != nil {
		defer func() { err = errors.Join(err, session.Close()) }()
	}
	if err != nil {
		return err
	}
	if session == nil || len(cpim) == 0 || len(cpim) > maxResponseBytes {
		return errors.New("missing or invalid commerce provisioning session")
	}
	body, err := plist.Marshal(map[string]any{"guid": guid, "clientData": base64.StdEncoding.EncodeToString(cpim)}, plist.XMLFormat)
	if err != nil {
		return errors.New("encode commerce provisioning request failed")
	}
	defer clear(body)
	req, err := c.newPostRequest(ctx, CommerceAMDFinishURL, body, commerceContentType, headers)
	if err != nil {
		return err
	}
	req.GetBody = nil
	raw, _, err := c.send(req)
	if err != nil {
		return err
	}
	defer clear(raw)
	var fields map[string]any
	if _, err = plist.Unmarshal(raw, &fields); err != nil {
		return errors.New("invalid commerce provisioning plist")
	}
	// V1 keybag import is separate and has not been ported to this V1.5 flow.
	if kb, exists := fields["keybag"]; exists && kb != nil {
		if b, ok := kb.([]byte); !ok || len(b) != 0 {
			return errors.New("commerce provisioning requires unsupported keybag import")
		}
	}
	decode := func(key string) ([]byte, error) {
		s, ok := fields[key].(string)
		if !ok {
			return nil, errors.New("commerce provisioning field missing")
		}
		b, e := base64.StdEncoding.Strict().DecodeString(s)
		if e != nil || len(b) == 0 {
			clear(b)
			return nil, errors.New("invalid commerce provisioning data")
		}
		return b, nil
	}
	ptm, err := decode("settingInfo")
	if err != nil {
		return err
	}
	defer clear(ptm)
	tk, err := decode("transportKey")
	if err != nil {
		return err
	}
	defer clear(tk)
	if err := ctx.Err(); err != nil {
		return err
	}
	return session.Finish(ctx, ptm, tk)
}
