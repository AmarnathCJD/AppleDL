package applemusic

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"
)

var ErrDeviceMetadata = errors.New("invalid Apple Music device metadata")

// DeviceMetadata is a snapshot of the matching app's device and bundle getters.
// DeviceID and StableID identify the device. Do not log or persist this struct.
// Use the app's UserAgent.create result; HardwarePlatform is the native ABI label
// (confirmed: arm64 and x64), not Android's hardwareType/model or host GOARCH.
type DeviceMetadata struct {
	Manufacturer     string `json:"manufacturer"`
	Model            string `json:"model"`
	PlatformName     string `json:"platformName"`
	PlatformVersion  string `json:"platformVersion"`
	BuildVersion     string `json:"buildVersion"`
	HardwarePlatform string `json:"hardwarePlatform"`
	BundleIdentifier string `json:"bundleIdentifier"`
	BundleName       string `json:"bundleName"`
	BundleVersion    string `json:"bundleVersion"`
	UserAgent        string `json:"userAgent"`
	DeviceID         string `json:"deviceId"`
	StableID         string `json:"stableId"`
	Language         string `json:"language"`
	BuildType        uint8  `json:"buildType"`
}

func (DeviceMetadata) String() string   { return "DeviceMetadata{redacted}" }
func (DeviceMetadata) GoString() string { return "DeviceMetadata{redacted}" }

// stripClientInfoWhitespace matches the native byte predicate at ELF 0x7057a8:
// remove every ASCII space or byte 0x09..0x0d, leaving Unicode whitespace intact.
func stripClientInfoWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || (r >= '\t' && r <= '\r') {
			return -1
		}
		return r
	}, s)
}

func validMetadataText(s string) bool {
	if len(s) > 4096 || !utf8.ValidString(s) {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// ClientInfo formats X-MMe-Client-Info as observed in AuthKitAndroid/1.0.
// Device components have ASCII whitespace removed. Bundle name/version are raw.
// Empty manufacturer/model strings stay empty, as in the concrete Java adapter.
func (m DeviceMetadata) ClientInfo() (string, error) {
	parts := []string{m.Manufacturer, m.Model, m.PlatformName, m.PlatformVersion, m.BuildVersion, m.HardwarePlatform}
	for i, s := range parts {
		if len(s) > 4096 || !utf8.ValidString(s) {
			return "", ErrDeviceMetadata
		}
		parts[i] = stripClientInfoWhitespace(s)
		if !validMetadataText(parts[i]) {
			return "", ErrDeviceMetadata
		}
	}
	if !validMetadataText(m.BundleName) || !validMetadataText(m.BundleVersion) {
		return "", ErrDeviceMetadata
	}
	maker, model, platform, version, build, hardware := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
	value := "<" + maker + "> <" + platform + ";" + version + ";" + platform + "/" + version + " build/" + build + " maker/" + maker + " model/" + model
	if m.HardwarePlatform != "" {
		value += " FW/" + hardware
	}
	value += "> <com.apple.AuthKitAndroid/1.0 (" + m.BundleName + "/" + m.BundleVersion + ")>"
	if len(value) > 16*1024 {
		return "", ErrDeviceMetadata
	}
	return value, nil
}

// IdMSHeaders returns the statically traced base headers, without Anisette,
// cookies, account-dependent HB tokens or content type. It does not certify a
// complete authentication/provisioning request. Returned values are sensitive.
func (m DeviceMetadata) IdMSHeaders() (http.Header, error) {
	clientInfo, err := m.ClientInfo()
	if err != nil {
		return nil, err
	}
	for _, s := range []string{m.UserAgent, m.DeviceID, m.StableID, m.Language, m.BundleIdentifier} {
		if s == "" || !validMetadataText(s) || strings.TrimSpace(s) != s {
			return nil, ErrDeviceMetadata
		}
	}
	h := http.Header{}
	h.Set("User-Agent", m.UserAgent)
	h.Set("X-MMe-Client-Info", clientInfo)
	h.Set("X-Apple-I-MD-RInfo", "0")
	h.Set("X-AppleId-Device-UDID", m.DeviceID)
	h.Set("X-MME-Device-Id", m.DeviceID)
	h.Set("X-Apple-I-Stable-Id", m.StableID)
	h.Set("Accept-Language", m.Language)
	h.Set("X-Apple-I-Client-Bundle-Id", "com.apple.AuthKitAndroid")
	h.Set("X-Apple-I-Proxied-Bundle-Id", m.BundleIdentifier)
	if m.BuildType != 0 {
		h.Set("X-Apple-I-88CC-99DE-EE63-2736", "true")
	}
	return h, nil
}
