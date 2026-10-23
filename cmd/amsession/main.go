// amsession exchanges saved commerce state for an in-memory media token and
// optionally checks catalog access. It never reads a password or starts Android.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

func run(ctx context.Context, args []string, output io.Writer) (err error) {
	fs := flag.NewFlagSet("amsession", flag.ContinueOnError)
	fs.SetOutput(output)
	cfg := standalone.Config{}

	fs.StringVar(&cfg.StateDir, "state", filepath.Join(".applemusic", "device"), "encrypted standalone device and account state")
	term := fs.String("term", "", "optional catalog search; first result is also looked up with extended assets")
	country := fs.String("country", "", "required with -term: two-letter catalog country, independent of account storefront")
	limit := fs.Int("limit", 3, "catalog search result limit, 1 through 25")
	assets := fs.Bool("assets", false, "also request the APK web-playback asset descriptor for the first catalog result")
	hls := fs.Bool("hls", false, "inspect enhancedHls and up to three child playlists; output redacted format and encryption counts")
	spc := fs.Bool("spc", false, "generate SPCs for the unique ALAC variant's referenced keys; no license POST")
	license := fs.Bool("license", false, "request and load live licenses for the unique ALAC variant")
	decrypt := fs.String("decrypt-alac", "", "acquire, license and decrypt ALAC into a new directory")
	workers := fs.Int("decrypt-workers", 0, "independent ALAC workers (0: automatic, 1..64: explicit)")
	exportContext := fs.Bool("export-context", false, "export ciphertext and matching portable private Go context; requires -decrypt-alac")
	benchmark := fs.Bool("decrypt-benchmark", false, "compare 8/12/16/20/24/32 workers three times using the same in-memory licenses")
	certificate := fs.String("playback-certificate", "", "optional public playback certificate; defaults to the embedded certificate")
	acquire := fs.String("acquire-hls", "", "save all encrypted segments and init data to a new directory; requires -hls-child")
	child := fs.Int("hls-child", -1, "diagnostic direct child index for acquisition, starting at 1; 0 for a media root")
	codec := fs.String("hls-codec", "", "select a unique declared codec for acquisition, e.g. alac; alternative to -hls-child")
	progress := fs.String("progress", "", "new redacted progress file; existing files are never replaced")
	timeout := fs.Duration("timeout", 0, "whole-session timeout (default 5m, or 30m for ALAC decryption)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.StateDir, err = filepath.Abs(cfg.StateDir)
	if err != nil {
		return errors.New("invalid state path")
	}
	if *workers < 0 || *workers > 64 || ((*benchmark || *exportContext) && *decrypt == "") {
		return errors.New("invalid decryption worker or benchmark options")
	}
	if *decrypt != "" {
		*license = true
		if *acquire != "" {
			return errors.New("select either ALAC decryption or separate acquisition")
		}
		if _, e := os.Lstat(*decrypt); !os.IsNotExist(e) {
			return errors.New("ALAC destination must be a new directory")
		}
	}
	if fs.NArg() != 0 || *limit < 1 || *limit > 25 {
		return errors.New("invalid session arguments")
	}
	if *timeout < 0 {
		return errors.New("session timeout must be positive")
	}
	if *timeout == 0 {
		*timeout = 5 * time.Minute
		if *decrypt != "" {
			*timeout = 30 * time.Minute
		}
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if *term != "" && (len(*country) != 2 || (*country)[0] < 'a' || (*country)[0] > 'z' || (*country)[1] < 'a' || (*country)[1] > 'z') {
		return errors.New("catalog search requires a lowercase two-letter country")
	}
	if (*assets || *hls || *spc || *license || *acquire != "") && *term == "" {
		return errors.New("asset inspection requires a search term")
	}
	if (*acquire != "" && (*child >= 0) == (*codec != "")) || (*acquire == "" && (*child != -1 || *codec != "")) {
		return errors.New("HLS acquisition requires exactly one child index or codec selector")
	}
	if *codec != "" && *codec != "alac" && *codec != "mp4a.40.2" && *codec != "mp4a.40.5" {
		return errors.New("unsupported diagnostic codec selector")
	}
	if *acquire != "" {
		if _, e := os.Lstat(*acquire); !os.IsNotExist(e) {
			return errors.New("acquisition destination must be a new directory")
		}
	}
	if *progress != "" {
		f, e := os.OpenFile(*progress, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return errors.New("cannot create new progress file")
		}
		defer func() { err = errors.Join(err, f.Close()) }()
		output = io.MultiWriter(output, f)
	}
	defer func() {
		if err != nil {
			fmt.Fprintln(output, "Session stopped:", err)
		}
	}()
	fmt.Fprintln(output, "Started UTC:", time.Now().UTC().Format(time.RFC3339))
	d, err := standalone.Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, d.Close()) }()
	saved, err := d.LoadCommerceResponse(ctx)
	if err != nil {
		return err
	}
	defer saved.Destroy()
	r, err := saved.Response()
	if err != nil {
		return err
	}
	defer r.Destroy()
	session, err := am.NewMediaTokenSession(r, saved.ObtainedAt)
	if err != nil {
		return err
	}
	defer session.Destroy()
	account, err := r.ExtractAccount()
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Loaded encrypted commerce state bound to the standalone device. No password exchange.")
	m, err := d.Metadata(ctx)
	if err != nil {
		return err
	}
	c, err := am.New(am.Config{})
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Fetching and validating AndroidMusic media-token policy.")
	p, err := c.FetchMediaTokenProfile(ctx, m.UserAgent)
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Preparing local SAP signing session.")
	signer, err := standalone.NewSAPSigner(ctx, cfg, m.StableID)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, signer.Close()) }()
	if err = signer.Setup(ctx, nil, am.SAPCertURL, am.SAPSetupURL, m.UserAgent); err != nil {
		return err
	}
	fmt.Fprintln(output, "Requesting media token with fresh device headers and action signature.")
	token, err := c.FetchMediaToken(ctx, p, session, m, d.MediaTokenPreparer(signer))
	if err != nil {
		return err
	}
	defer token.Destroy()
	fmt.Fprintln(output, "Media token received; retained only in this process.")
	if *term == "" {
		return nil
	}
	media, err := am.NewMedia(am.MediaConfig{BearerToken: token.Token, DSID: strconv.FormatUint(account.DSID, 10), UserAgent: m.UserAgent, Storefront: *country})
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Checking authenticated catalog search.")
	search, err := media.SearchSongs(ctx, *term, am.SearchOptions{Limit: *limit})
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Catalog search accepted. Song count: %d\n", len(search.Results.Songs.Data))
	if len(search.Results.Songs.Data) == 0 {
		return nil
	}
	id := search.Results.Songs.Data[0].ID
	fmt.Fprintln(output, "Checking first song metadata with extended asset fields.")
	page, err := media.Songs(ctx, []string{id}, am.SongOptions{ExtendedAssets: true})
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Song metadata accepted. Song count: %d\n", len(page.Data))
	for _, song := range page.Data {
		a := song.Attributes
		fmt.Fprintf(output, "Metadata present: title=%t artist=%t album=%t duration=%t ISRC=%t artwork=%t playParams=%t\n", a.Name != "", a.ArtistName != "", a.AlbumName != "", a.DurationInMillis > 0, a.ISRC != "", a.Artwork != nil, a.PlayParams != nil)
		fmt.Fprintf(output, "Preview count: %d; extended asset flavor count: %d; asset-token count: %d\n", len(a.Previews), len(a.ExtendedAssetURLs), len(a.AssetTokens))
		for _, flavor := range []string{"plus", "lightweightPlus", "lightweight", "superLight", "enhancedHls"} {
			fmt.Fprintf(output, "Extended asset %s present: %t\n", flavor, a.ExtendedAssetURLs[flavor] != "")
		}
	}
	if *hls || *spc || *license || *acquire != "" {
		if len(page.Data) == 0 || page.Data[0].Attributes.ExtendedAssetURLs["enhancedHls"] == "" {
			return errors.New("enhancedHls is absent from the first song metadata result")
		}
		cache := map[string]*am.HLSManifest{}
		fetch := func(ctx context.Context, rawURL string) (*am.HLSManifest, error) {
			if manifest, ok := cache[rawURL]; ok {
				return manifest, nil
			}
			manifest, e := am.FetchHLS(ctx, nil, rawURL)
			if e == nil {
				cache[rawURL] = manifest
			}
			return manifest, e
		}
		root := page.Data[0].Attributes.ExtendedAssetURLs["enhancedHls"]
		if *license {
			profile, err := c.FetchPlaybackProfile(ctx, m.UserAgent)
			if err != nil {
				return err
			}
			playbackSession, err := am.NewPlaybackSession(r, saved.ObtainedAt)
			if err != nil {
				return err
			}
			defer playbackSession.Destroy()
			if err := probeALACLicense(ctx, output, cfg, m, *certificate, root, id, fetch, c, profile, playbackSession, d.PlaybackPreparer(), *decrypt, *workers, *benchmark, *exportContext); err != nil {
				return err
			}
		}
		if *spc {
			if err := probeALACSPC(ctx, output, cfg, m.StableID, *certificate, root, fetch); err != nil {
				return err
			}
		}
		if *hls {
			if err := inspectHLS(ctx, output, root, fetch); err != nil {
				return err
			}
		}
		if *acquire != "" {
			if err := acquireSelectedHLS(ctx, output, root, *child, *codec, *acquire, m.UserAgent, m.Language, fetch); err != nil {
				return err
			}
		}
	}
	if *assets {
		fmt.Fprintln(output, "Requesting the APK web-playback asset descriptor.")
		result, err := media.PlayAssets(ctx, id)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Web-playback asset request accepted. Asset count: %d\n", len(result.Results.Assets))
		for _, asset := range result.Results.Assets {
			desc, err := asset.Describe()
			if err != nil {
				return err
			}
			fmt.Fprintf(output, "Asset: transport=%s protection=%s keyServer=%t certificate=%t\n", desc.Transport, desc.Protection, desc.KeyServerURL != "", desc.CertificateURL != "")
		}
	}
	fmt.Fprintln(output, "Session checks complete.")
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Session check failed:", err)
		os.Exit(1)
	}
}
