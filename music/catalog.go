package music

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	am "github.com/AmarnathCJD/AppleDL"
)

type SearchOptions = am.SearchOptions

// Format describes an advertised HLS variant. DownloadSupported indicates an
// implemented codec path, not a guarantee of entitlement or a usable license.
// Bandwidth is advertised bits/second. Exact bit depth and sample rate are only
// known after acquisition and are returned in DownloadResult.
type Format struct {
	ID                string
	Codec             string
	Bandwidth         int64
	DownloadSupported bool
}

// Song contains public catalog metadata. GetSong also populates Formats;
// Search and NextSongs omit formats to avoid a manifest request per result.
// Signed asset URLs, cookies and asset tokens are never returned here.
type Song struct {
	ID          string
	Name        string
	Artist      string
	Album       string
	Composer    string
	Duration    time.Duration
	ISRC        string
	ReleaseDate string
	Genres      []string
	TrackNumber int
	DiscNumber  int
	Artwork     *am.Artwork
	Formats     []Format
}

type SearchResult struct {
	Songs []Song
	Next  string
}

func publicSong(s am.Song) Song {
	a := s.Attributes
	return Song{ID: s.ID, Name: a.Name, Artist: a.ArtistName, Album: a.AlbumName,
		Composer: a.ComposerName, Duration: time.Duration(a.DurationInMillis) * time.Millisecond,
		ISRC: a.ISRC, ReleaseDate: a.ReleaseDate, Genres: append([]string(nil), a.GenreNames...),
		TrackNumber: a.TrackNumber, DiscNumber: a.DiscNumber, Artwork: a.Artwork}
}

func publicPage(page am.SongPage) *SearchResult {
	out := &SearchResult{Songs: make([]Song, 0, len(page.Data)), Next: page.Next}
	for _, s := range page.Data {
		out.Songs = append(out.Songs, publicSong(s))
	}
	return out
}

// mediaGET retries one read after HTTP 401 by refreshing the saved session.
// It never retries passwords, device challenges, license requests or HTTP 403.
func (c *Client) mediaGET(ctx context.Context, read func(*am.MediaClient) error) error {
	if c.state == nil {
		return ErrSessionRequired
	}
	err := read(c.state.media)
	var status *am.MediaHTTPError
	if errors.As(err, &status) && status.StatusCode == http.StatusUnauthorized {
		if err := c.refresh(ctx); err != nil {
			return err
		}
		return read(c.state.media)
	}
	return err
}

// Search finds songs; omit options for the API's default page size of 25.
func (c *Client) Search(ctx context.Context, term string, options ...SearchOptions) (*SearchResult, error) {
	if len(options) > 1 {
		return nil, errors.New("provide at most one search options value")
	}
	var opts SearchOptions
	if len(options) == 1 {
		opts = options[0]
	}
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	var response *am.SearchResponse
	err := c.mediaGET(ctx, func(m *am.MediaClient) (err error) { response, err = m.SearchSongs(ctx, term, opts); return })
	if err != nil {
		return nil, err
	}
	return publicPage(response.Results.Songs), nil
}

// NextSongs follows the Next value returned by Search or a previous page.
func (c *Client) NextSongs(ctx context.Context, next string) (*SearchResult, error) {
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	var page *am.SongPage
	err := c.mediaGET(ctx, func(m *am.MediaClient) (err error) { page, err = m.NextSongs(ctx, next); return })
	if err != nil {
		return nil, err
	}
	return publicPage(*page), nil
}

type songAssets struct {
	song     Song
	variants []am.HLSVariant
}

func variantFormats(variants []am.HLSVariant) []Format {
	out := make([]Format, 0, len(variants))
	seen := make(map[string]int)
	for _, v := range variants {
		// Exclude rotating signed URLs so an ID survives a refreshed manifest.
		key := fmt.Sprintf("%s\x00%d\x00%s", v.Codecs, v.Bandwidth, v.Audio)
		seen[key]++
		digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", key, seen[key])))
		out = append(out, Format{ID: hex.EncodeToString(digest[:12]), Codec: v.Codecs,
			Bandwidth: v.Bandwidth, DownloadSupported: strings.TrimSpace(v.Codecs) == "alac"})
	}
	return out
}

func (c *Client) songAssets(ctx context.Context, id string) (*songAssets, error) {
	var page *am.SongPage
	err := c.mediaGET(ctx, func(m *am.MediaClient) (err error) {
		page, err = m.Songs(ctx, []string{id}, am.SongOptions{ExtendedAssets: true})
		return
	})
	if err != nil {
		return nil, err
	}
	var selected *am.Song
	for i := range page.Data {
		if page.Data[i].ID == id {
			selected = &page.Data[i]
			break
		}
	}
	if selected == nil {
		return nil, ErrSongNotFound
	}
	out := &songAssets{song: publicSong(*selected)}
	root := selected.Attributes.ExtendedAssetURLs["enhancedHls"]
	if root == "" {
		return out, nil
	}
	manifest, err := am.FetchHLS(ctx, c.cfg.HTTPClient, root)
	if err != nil {
		return nil, err
	}
	out.variants = manifest.Variants
	out.song.Formats = variantFormats(manifest.Variants)
	return out, nil
}

// GetSong retrieves metadata and the currently advertised HLS formats.
func (c *Client) GetSong(ctx context.Context, id string) (*Song, error) {
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	assets, err := c.songAssets(ctx, id)
	if err != nil {
		return nil, err
	}
	return &assets.song, nil
}
