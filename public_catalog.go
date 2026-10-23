package applemusic

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// PublicCatalog is the separate public iTunes Search API. It is NOT the APK's
// AMP API and neither verifies Apple Music login nor returns full-track access.
type PublicCatalog struct{ http *http.Client }

func NewPublicCatalog(hc *http.Client) *PublicCatalog { return &PublicCatalog{newMediaHTTP(hc)} }

type PublicTrack struct {
	WrapperType       string `json:"wrapperType"`
	Kind              string `json:"kind"`
	TrackID           int64  `json:"trackId"`
	TrackName         string `json:"trackName"`
	ArtistID          int64  `json:"artistId,omitempty"`
	ArtistName        string `json:"artistName"`
	CollectionID      int64  `json:"collectionId,omitempty"`
	CollectionName    string `json:"collectionName"`
	TrackTimeMillis   int64  `json:"trackTimeMillis"`
	ReleaseDate       string `json:"releaseDate"`
	PrimaryGenreName  string `json:"primaryGenreName"`
	TrackNumber       int    `json:"trackNumber"`
	DiscNumber        int    `json:"discNumber"`
	TrackExplicitness string `json:"trackExplicitness"`
	TrackViewURL      string `json:"trackViewUrl"`
	ArtworkURL100     string `json:"artworkUrl100"`
	PreviewURL        string `json:"previewUrl"`
	Country           string `json:"country"`
}
type PublicTracks struct {
	ResultCount int           `json:"resultCount"`
	Results     []PublicTrack `json:"results"`
}

func (c *PublicCatalog) get(ctx context.Context, path string, q url.Values) (*PublicTracks, error) {
	u := url.URL{Scheme: "https", Host: "itunes.apple.com", Path: path, RawQuery: q.Encode()}
	var out PublicTracks
	if err := mediaJSON(ctx, c.http, u.String(), nil, &out); err != nil {
		return nil, err
	}
	if out.Results == nil || out.ResultCount != len(out.Results) {
		return nil, errors.New("invalid public catalog results")
	}
	return &out, nil
}
func (c *PublicCatalog) SearchSongs(ctx context.Context, term, country string, limit int) (*PublicTracks, error) {
	if !countryCode(country) || strings.TrimSpace(term) == "" || limit < 1 || limit > 200 {
		return nil, errors.New("public search requires term, two-letter country and limit 1..200")
	}
	return c.get(ctx, "/search", url.Values{"term": {term}, "country": {country}, "entity": {"song"}, "media": {"music"}, "limit": {strconv.Itoa(limit)}})
}
func (c *PublicCatalog) LookupSongs(ctx context.Context, ids []string, country string) (*PublicTracks, error) {
	if !countryCode(country) || len(ids) == 0 || len(ids) > 100 {
		return nil, errors.New("public lookup requires 1..100 IDs and a two-letter country")
	}
	for _, id := range ids {
		if !catalogID(id) {
			return nil, errors.New("public track IDs must be decimal strings")
		}
	}
	return c.get(ctx, "/lookup", url.Values{"id": {strings.Join(ids, ",")}, "country": {country}, "entity": {"song"}})
}
