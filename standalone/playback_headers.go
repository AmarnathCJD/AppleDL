package standalone

import (
	"context"
	"errors"
	"net/http"

	am "github.com/AmarnathCJD/AppleDL"
)

func (d *Device) PlaybackPreparer() am.PlaybackRequestPreparer {
	return func(ctx context.Context, req am.PlaybackRequestPlan) (http.Header, error) {
		if req.URL != am.PlaybackLicenseURL || req.Method != http.MethodPost {
			return nil, errors.New("unsupported playback preparation target")
		}
		m, err := d.Metadata(ctx)
		if err != nil {
			return nil, err
		}
		if req.Headers.Get("X-Guid") != m.StableID {
			return nil, errors.New("playback device identity mismatch")
		}
		h := req.Headers.Clone()
		otp, err := d.AnisetteHeaders(ctx, am.AnisetteV15DSID)
		if err != nil {
			return nil, err
		}
		for key, values := range otp {
			h[key] = append([]string(nil), values...)
		}
		return h, nil
	}
}
