package applemusic

import (
	"context"
	"errors"
	"net/url"
	"strings"
)

type PlayAsset struct {
	URL                       string `json:"url"`
	KeyServerURL              string `json:"keyServerUrl,omitempty"`
	FairPlayKeyCertificateURL string `json:"fairPlayKeyCertificateUrl,omitempty"`
	BitRate                   *int   `json:"bitRate,omitempty"`
}
type PlayAssetsResponse struct {
	Results struct {
		Assets []PlayAsset `json:"assets"`
	} `json:"results"`
}

// PlayAssets mirrors WebPlaybackRequest: GET, kind=song, CBC, enhancedHls.
// The app uses this in web-playback branches, not as its only asset mechanism.
// The returned URLs can be signed/expiring; do not log them as diagnostics.
func (c *MediaClient) PlayAssets(ctx context.Context, id string) (*PlayAssetsResponse, error) {
	if strings.TrimSpace(id) == "" || len(id) > 256 {
		return nil, errors.New("playback ID required")
	}
	q := url.Values{"id": {id}, "kind": {"song"}, "hlsEncryption": {"CBC"}, "hlsProfile": {"enhancedHls"}}
	var out PlayAssetsResponse
	if err := c.get(ctx, mediaCatalogHost, "/v1/play/assets", q, &out); err != nil {
		return nil, err
	}
	if out.Results.Assets == nil {
		return nil, errors.New("media play assets missing")
	}
	return &out, nil
}

type AssetDescriptor struct {
	Transport         string `json:"transport"`
	Flavor            string `json:"flavor"`
	Protection        string `json:"protection"`
	URL               string `json:"url"`
	KeyServerURL      string `json:"keyServerUrl,omitempty"`
	CertificateURL    string `json:"certificateUrl,omitempty"`
	KeyServerProtocol string `json:"keyServerProtocol,omitempty"`
}

// Describe follows WebPlaybackRequest's HLS mapping. Progressive transport
// alone does not prove that a full-track file is unencrypted or playable.
func (a PlayAsset) Describe() (AssetDescriptor, error) {
	u, err := url.Parse(a.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return AssetDescriptor{}, errors.New("invalid play asset URL")
	}
	d := AssetDescriptor{Transport: "progressive", Flavor: "LW", Protection: "unknown", URL: a.URL}
	if strings.HasSuffix(strings.ToLower(u.Path), ".m3u8") {
		d.Transport, d.Flavor, d.Protection = "hls", "HLS", "pastis-fmp4"
		d.KeyServerURL, d.CertificateURL = a.KeyServerURL, a.FairPlayKeyCertificateURL
		if d.KeyServerURL == "" {
			d.KeyServerURL = "https://play.itunes.apple.com/WebObjects/MZPlay.woa/music/fps"
		}
		if d.CertificateURL == "" {
			d.CertificateURL = "https://s.mzstatic.com/skdtool_2021_certbundle.bin"
		}
		d.KeyServerProtocol = "simplified"
	}
	return d, nil
}
