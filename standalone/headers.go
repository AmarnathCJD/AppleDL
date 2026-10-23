package standalone

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/AmarnathCJD/AppleDL"
)

// localGUID follows foothill.impl.d.a(), with its explicit missing-hardware
// fallback for the properties and MAC fields. This runtime has neither Android
// hardware properties nor an Android network interface. The fourth field is
// the LAST 14 lowercase hex characters of SHA-1(Android-ID UTF-8 text).
func localGUID(id string) string {
	digest := sha1.Sum([]byte(id))
	hash := hex.EncodeToString(digest[:])
	return strings.Repeat("0", 36) + "." + strings.Repeat("0", 14) +
		".00000000000001." + hash[len(hash)-14:] + "." + strings.Repeat("0", 14) + "." + strings.Repeat("0", 14)
}

// Metadata uses the observed Android 15 / Music 7.0.0 protocol profile, with
// this runtime's ARM64 ABI and its OWN local identity. It does not describe the
// Windows host or import any identifier from the signed-in Android app.
func (d *Device) Metadata(ctx context.Context) (m applemusic.DeviceMetadata, err error) {
	err = d.run(ctx, true, func() error {
		m = applemusic.DeviceMetadata{
			Manufacturer: "Google", Model: "Pixel9", PlatformName: "Android",
			PlatformVersion: "15", BuildVersion: "1606", HardwarePlatform: "arm64",
			BundleIdentifier: "musicAndroid", BundleName: "Music", BundleVersion: "7.0.0",
			UserAgent: "Music/7.0.0 Android/15 model/GooglePixel9 build/1606 (dt:66) AMS/1",
			DeviceID:  localGUID(d.state.AndroidID), StableID: d.state.AndroidID, Language: "en-US",
		}
		return nil
	})
	return
}

// ProvisioningHeaders contains base metadata only: OTPs do not exist until
// provisioning finishes. Metadata may be read while a provisioning session runs.
func (d *Device) ProvisioningHeaders(ctx context.Context, _ applemusic.ProvisioningStep) (http.Header, error) {
	m, err := d.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	return m.IdMSHeaders()
}

// IdMSDeviceHeaders obtains a new V3 OTP for each SRP request. Account-dependent
// cookies/HB headers and commerce signing are separate from this provider.
func (d *Device) IdMSDeviceHeaders(ctx context.Context, _ applemusic.SRPStep) (http.Header, error) {
	h, err := d.ProvisioningHeaders(ctx, "")
	if err != nil {
		return nil, err
	}
	otp, err := d.AnisetteHeaders(ctx, applemusic.AnisetteV3DSID)
	if err != nil {
		return nil, err
	}
	for key, values := range otp {
		h[key] = values
	}
	return h, nil
}
