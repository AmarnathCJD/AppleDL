package standalone

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/AmarnathCJD/AppleDL"
)

// CommercePreparer binds the reviewed bag, local device and initialized signer.
// An unprovisioned V1.5 device omits AMD headers so Apple can issue an SP challenge.
func (d *Device) CommercePreparer(profile *applemusic.CommerceProfile, signer *SAPSigner) applemusic.CommerceRequestPreparer {
	return func(ctx context.Context, req applemusic.CommerceRequest) (http.Header, error) {
		if req.URL != applemusic.CommerceAuthURL || req.Method != "POST" || signer == nil {
			return nil, errors.New("unsupported standalone commerce request")
		}
		m, err := d.Metadata(ctx)
		if err != nil {
			return nil, err
		}
		if signer.identity != m.StableID {
			return nil, errors.New("commerce signer identity mismatch")
		}
		h, err := profile.Headers(m)
		if err != nil {
			return nil, err
		}
		for k, v := range req.Headers {
			key := http.CanonicalHeaderKey(k)
			if key != "Content-Type" && key != "Accept" && key != "X-Apple-Ignore-Account-Conversion" {
				return nil, errors.New("unsupported standalone commerce request header")
			}
			h[key] = append([]string(nil), v...)
		}
		status, err := d.Status(ctx, applemusic.AnisetteV15DSID)
		if err != nil {
			return nil, err
		}
		switch status {
		case 0:
			otp, e := d.AnisetteHeaders(ctx, applemusic.AnisetteV15DSID)
			if e != nil {
				return nil, e
			}
			for k, v := range otp {
				h[k] = v
			}
		case -45061:
			h.Del("X-Apple-AMD")
			h.Del("X-Apple-AMD-M")
		default:
			return nil, &StatusError{Operation: "commerce device status", Code: status}
		}
		signature, err := signer.Sign(ctx, req.Body)
		if err != nil {
			return nil, err
		}
		defer clear(signature)
		h.Set("X-Apple-ActionSignature", base64.StdEncoding.EncodeToString(signature))
		return h, nil
	}
}
