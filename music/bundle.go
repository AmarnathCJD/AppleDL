package music

import (
	"context"
	"io"
	"time"

	"github.com/AmarnathCJD/AppleDL/internal/playback"
)

// BundleResult describes offline replay of an exported matching context.
type BundleResult struct {
	Path           string
	Workers        int
	Samples        int
	SampleRate     uint32
	BitDepth       uint8
	Channels       uint8
	SetupDuration  time.Duration
	SampleDuration time.Duration
	TotalDuration  time.Duration
}

// DecryptBundle verifies an encrypted file against its exported .amctx bundle
// and writes a NEW output file. It requires no Client, account or network.
// Workers accepts 0 (automatic) or 1..64. Progress may be nil.
func DecryptBundle(ctx context.Context, encryptedPath, contextPath, outputPath string, workers int, progress io.Writer) (*BundleResult, error) {
	r, err := playback.DecryptBundle(ctx, encryptedPath, contextPath, outputPath, workers, progress)
	if err != nil {
		return nil, err
	}
	return &BundleResult{Path: r.Path, Workers: r.Workers, Samples: r.Samples,
		SampleRate: r.SampleRate, BitDepth: r.BitDepth, Channels: r.Channels,
		SetupDuration: r.SetupDuration, SampleDuration: r.SampleDuration, TotalDuration: r.TotalDuration}, nil
}
