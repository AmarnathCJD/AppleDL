package standalone

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/AmarnathCJD/AppleDL"
)

// MediaTokenPreparer uses the local provisioned V1.5 identity and SAP session.
// It signs the apiToken policy's selected values, not a commerce POST body.
func (d *Device) MediaTokenPreparer(signer *SAPSigner) applemusic.MediaTokenRequestPreparer {
	return func(ctx context.Context, req applemusic.MediaTokenRequest) (http.Header, error) {
		if signer == nil {
			return nil, errors.New("media-token signer required")
		}
		m, err := d.Metadata(ctx)
		if err != nil {
			return nil, err
		}
		if signer.identity != m.StableID {
			return nil, errors.New("media-token signer identity mismatch")
		}
		h := req.Headers.Clone()
		otp, err := d.AnisetteHeaders(ctx, applemusic.AnisetteV15DSID)
		if err != nil {
			return nil, err
		}
		for key, values := range otp {
			h[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
		}
		req.Headers = h
		data, err := applemusic.MediaTokenSigningData(req)
		if err != nil {
			return nil, err
		}
		defer clear(data)
		sig, err := signer.Sign(ctx, data)
		if err != nil {
			return nil, err
		}
		defer clear(sig)
		h.Set("X-Apple-ActionSignature", base64.StdEncoding.EncodeToString(sig))
		return h, nil
	}
}
