// ammedia exposes catalog research and bounded media-file inspection.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"

	am "github.com/AmarnathCJD/AppleDL"
)

type songSummary struct {
	ID                   string            `json:"id"`
	Attributes           am.SongAttributes `json:"metadata"`
	PreviewCount         int               `json:"previewCount"`
	ExtendedAssetFlavors []string          `json:"extendedAssetFlavors,omitempty"`
}

func summarizeSongs(page *am.SongPage) any {
	items := make([]songSummary, 0, len(page.Data))
	for _, song := range page.Data {
		a := song.Attributes
		flavors := make([]string, 0, len(a.ExtendedAssetURLs))
		for flavor := range a.ExtendedAssetURLs {
			flavors = append(flavors, flavor)
		}
		sort.Strings(flavors)
		count := len(a.Previews)
		// Keep account-specific asset URLs, tokens and offers out of CLI logs.
		a.Previews, a.ExtendedAssetURLs, a.AssetTokens, a.Offers = nil, nil, nil, nil
		items = append(items, songSummary{song.ID, a, count, flavors})
	}
	return map[string]any{"source": "android-amp", "songs": items, "hasNext": page.Next != ""}
}

func summarizePublic(result *am.PublicTracks) any {
	items := make([]map[string]any, 0, len(result.Results))
	for _, track := range result.Results {
		items = append(items, map[string]any{
			"id": track.TrackID, "name": track.TrackName, "artist": track.ArtistName,
			"album": track.CollectionName, "durationInMillis": track.TrackTimeMillis,
			"releaseDate": track.ReleaseDate, "genre": track.PrimaryGenreName,
			"trackNumber": track.TrackNumber, "discNumber": track.DiscNumber,
			"contentRating": track.TrackExplicitness, "country": track.Country,
			"hasPreview": track.PreviewURL != "",
		})
	}
	return map[string]any{"source": "public-itunes", "songs": items, "count": result.ResultCount}
}

func summarizeHLS(m *am.HLSManifest) any {
	methods, formats := map[string]bool{}, map[string]bool{}
	for _, key := range m.Keys {
		methods[key.Method] = true
		formats[key.Format] = true
	}
	keys := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	duration := 0.0
	for _, segment := range m.Segments {
		duration += segment.Duration
	}
	return map[string]any{
		"source": "hls-inventory", "variants": len(m.Variants), "renditions": len(m.Renditions),
		"segments": len(m.Segments), "initMaps": len(m.Maps), "endList": m.EndList,
		"listedDurationSeconds": duration, "encryptionSignaled": m.EncryptionSignaled,
		"keyMethods": keys(methods), "keyFormats": keys(formats), "unhandledTags": m.UnhandledTags,
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("command required: public-search, public-song, public-preview, search, song, suggestions, assets, inspect-hls")
	}
	command := args[0]
	switch command {
	case "public-search", "public-song", "public-preview", "search", "song", "suggestions", "assets", "inspect-hls":
	default:
		return errors.New("unknown media command")
	}
	fs := flag.NewFlagSet("ammedia "+command, flag.ContinueOnError)
	fs.SetOutput(output)
	term := fs.String("term", "", "search text")
	id := fs.String("id", "", "catalog song ID (comma-separated for song lookup)")
	country := fs.String("country", "us", "two-letter storefront")
	limit := fs.Int("limit", 10, "search result limit")
	offset := fs.Int("offset", 0, "AMP search offset")
	language := fs.String("language", "", "AMP language")
	extended := fs.Bool("extended", false, "request extended asset URLs and offers; output flavor names only")
	destination := fs.String("out", "", "new preview output file; parent directory must exist")
	file := fs.String("file", "", "local HLS playlist")
	baseURL := fs.String("base-url", "https://audio-ssl.itunes.apple.com/playlist.m3u8", "base for local playlist references")
	remote := fs.Bool("remote", false, "inspect one CDN playlist from APPLEMUSIC_HLS_URL")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	emit := func(value any) error {
		enc := json.NewEncoder(output)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	}

	if command == "inspect-hls" {
		var manifest *am.HLSManifest
		var err error
		if *remote {
			if *file != "" {
				return errors.New("choose local file or remote playlist")
			}
			manifest, err = am.FetchHLS(ctx, nil, os.Getenv("APPLEMUSIC_HLS_URL"))
		} else {
			f, openErr := os.Open(*file)
			if openErr != nil {
				return errors.New("cannot open local HLS playlist")
			}
			defer f.Close()
			manifest, err = am.ParseHLS(f, *baseURL)
		}
		if err != nil {
			return err
		}
		return emit(summarizeHLS(manifest))
	}

	if strings.HasPrefix(command, "public-") {
		catalog := am.NewPublicCatalog(nil)
		var result *am.PublicTracks
		var err error
		if command == "public-search" {
			result, err = catalog.SearchSongs(ctx, *term, *country, *limit)
		} else {
			result, err = catalog.LookupSongs(ctx, strings.Split(*id, ","), *country)
		}
		if err != nil {
			return err
		}
		if command != "public-preview" {
			return emit(summarizePublic(result))
		}
		if *destination == "" || strings.Contains(*id, ",") {
			return errors.New("public-preview requires one ID and -out")
		}
		for _, track := range result.Results {
			if fmt.Sprint(track.TrackID) != *id || track.Kind != "song" || track.PreviewURL == "" {
				continue
			}
			file, err := am.DownloadPreview(ctx, nil, am.Preview{URL: track.PreviewURL}, *destination)
			if err != nil {
				return err
			}
			return emit(map[string]any{"source": "public-itunes-preview", "id": track.TrackID, "file": file})
		}
		return errors.New("catalog returned no progressive preview for this song")
	}

	c, err := am.NewMedia(am.MediaConfig{
		BearerToken: os.Getenv("APPLEMUSIC_MEDIA_TOKEN"), DSID: os.Getenv("APPLEMUSIC_MEDIA_DSID"),
		UserAgent: os.Getenv("APPLEMUSIC_MEDIA_USER_AGENT"), Storefront: *country, Language: *language,
	})
	if err != nil {
		return err
	}
	switch command {
	case "search":
		result, err := c.SearchSongs(ctx, *term, am.SearchOptions{Limit: *limit, Offset: *offset})
		if err != nil {
			return err
		}
		return emit(summarizeSongs(&result.Results.Songs))
	case "song":
		result, err := c.Songs(ctx, strings.Split(*id, ","), am.SongOptions{ExtendedAssets: *extended})
		if err != nil {
			return err
		}
		return emit(summarizeSongs(result))
	case "suggestions":
		result, err := c.Suggestions(ctx, *term)
		if err != nil {
			return err
		}
		// Keep the complete heterogeneous payload available through the Go API.
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(result, &envelope); err != nil {
			return errors.New("invalid suggestions envelope")
		}
		fields := make([]string, 0, len(envelope))
		for field := range envelope {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		return emit(map[string]any{"source": "android-amp", "responseFields": fields, "bytes": len(result)})
	case "assets":
		result, err := c.PlayAssets(ctx, *id)
		if err != nil {
			return err
		}
		items := make([]map[string]any, 0, len(result.Results.Assets))
		for _, asset := range result.Results.Assets {
			desc, err := asset.Describe()
			if err != nil {
				return err
			}
			items = append(items, map[string]any{"transport": desc.Transport, "flavor": desc.Flavor, "protection": desc.Protection, "bitRate": asset.BitRate})
		}
		return emit(map[string]any{"source": "android-amp-web-playback", "assets": items})
	}
	return errors.New("unhandled media command")
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "ammedia:", err)
		os.Exit(1)
	}
}
