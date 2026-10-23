package music

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/internal/playback"
)

var ErrUnsupportedFormat = errors.New("requested format is unavailable or has no implemented download path")

type DownloadOptions struct {
	FormatID      string // empty selects the highest advertised ALAC bandwidth
	Workers       int    // 0 uses Config.Workers; otherwise 1..64
	ExportContext bool   // save a matching private context for offline replay
}

// DownloadResult describes the completed fragmented M4A file containing ALAC.
// SampleDuration includes fragment I/O. DecryptionDuration also includes setup
// and worker cloning, setup reads and cleanup. TotalDuration includes metadata,
// acquisition and licensing; constructor authentication is excluded.
type DownloadResult struct {
	Path                    string
	EncryptedPath           string
	ContextPath             string
	Format                  Format
	Workers                 int
	Samples                 int
	SampleRate              uint32
	BitDepth                uint8
	Channels                uint8
	EncryptedBytes          int64
	AcquisitionDuration     time.Duration
	LicenseDuration         time.Duration
	LicenseRuntimeDuration  time.Duration
	LicenseSPCDuration      time.Duration
	LicenseHeadersDuration  time.Duration
	LicenseExchangeDuration time.Duration
	LicenseCKCDuration      time.Duration
	SetupDuration           time.Duration
	CloneDuration           time.Duration
	SampleDuration          time.Duration
	DecryptionDuration      time.Duration
	TotalDuration           time.Duration
}

func selectFormat(formats []Format, id string) (int, error) {
	best := -1
	for i, f := range formats {
		if id != "" && f.ID == id {
			if !f.DownloadSupported {
				return -1, ErrUnsupportedFormat
			}
			return i, nil
		}
		if id == "" && f.DownloadSupported && (best < 0 || f.Bandwidth > formats[best].Bandwidth) {
			best = i
		}
	}
	if best < 0 {
		return -1, ErrUnsupportedFormat
	}
	return best, nil
}

// DownloadAndDecryptSong obtains fresh assets and licenses and writes ALAC to
// a NEW destination directory. It preserves encrypted acquisition files there.
// Errors can leave acquisition files, but never a partial decrypted output.
func (c *Client) DownloadAndDecryptSong(ctx context.Context, id, destination string, options ...DownloadOptions) (*DownloadResult, error) {
	if len(options) > 1 {
		return nil, errors.New("provide at most one download options value")
	}
	var opts DownloadOptions
	if len(options) == 1 {
		opts = options[0]
	}
	if opts.Workers < 0 || opts.Workers > 64 {
		return nil, errors.New("workers must be 0 through 64")
	}
	if destination == "" {
		return nil, errors.New("new destination directory required")
	}
	destination, err := filepath.Abs(destination)
	if err != nil {
		return nil, errors.New("invalid destination directory")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("destination must be a new directory")
	}
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	started := time.Now()
	assets, err := c.songAssets(ctx, id)
	if err != nil {
		return nil, err
	}
	index, err := selectFormat(assets.song.Formats, opts.FormatID)
	if err != nil {
		return nil, err
	}
	manifest, err := am.FetchHLS(ctx, c.cfg.HTTPClient, assets.variants[index].URL)
	if err != nil {
		return nil, err
	}
	m, err := c.state.device.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	profile, err := c.protocol.FetchPlaybackProfile(ctx, m.UserAgent)
	if err != nil {
		return nil, err
	}
	saved, err := c.state.device.LoadCommerceResponse(ctx)
	if err != nil {
		return nil, err
	}
	defer saved.Destroy()
	r, err := saved.Response()
	if err != nil {
		return nil, err
	}
	defer r.Destroy()
	session, err := am.NewPlaybackSession(r, saved.ObtainedAt)
	if err != nil {
		return nil, err
	}
	defer session.Destroy()
	workers := opts.Workers
	if workers == 0 {
		workers = c.cfg.Workers
	}
	result, err := playback.Run(ctx, playback.Config{
		Runtime: c.runtimeConfig(c.cfg.StateDir), Metadata: m, Manifest: manifest, AssetID: id,
		Protocol: c.protocol, Profile: profile, Session: session, Prepare: c.state.device.PlaybackPreparer(),
		HTTPClient: c.cfg.HTTPClient, Destination: destination, Workers: workers, Progress: c.cfg.Progress,
		ExportContext: opts.ExportContext,
	})
	if err != nil {
		return nil, err
	}
	return &DownloadResult{Path: result.Path, EncryptedPath: result.EncryptedPath, ContextPath: result.ContextPath, Format: assets.song.Formats[index], Workers: result.Workers,
		Samples: result.Samples, SampleRate: result.SampleRate, BitDepth: result.BitDepth, Channels: result.Channels,
		EncryptedBytes: result.EncryptedBytes, AcquisitionDuration: result.AcquisitionDuration,
		LicenseDuration: result.LicenseDuration, SetupDuration: result.SetupDuration, CloneDuration: result.CloneDuration,
		LicenseRuntimeDuration: result.LicenseRuntimeDuration, LicenseSPCDuration: result.LicenseSPCDuration,
		LicenseHeadersDuration: result.LicenseHeadersDuration, LicenseExchangeDuration: result.LicenseExchangeDuration, LicenseCKCDuration: result.LicenseCKCDuration,
		SampleDuration: result.SampleDuration, DecryptionDuration: result.DecryptionDuration,
		TotalDuration: time.Since(started)}, nil
}
