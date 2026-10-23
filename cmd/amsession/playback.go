package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/internal/playback"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

func probeALACLicense(ctx context.Context, out io.Writer, cfg standalone.Config, metadata am.DeviceMetadata, certificatePath, root, assetID string, fetch func(context.Context, string) (*am.HLSManifest, error), client *am.Client, profile *am.PlaybackProfile, session *am.PlaybackSession, prepare am.PlaybackRequestPreparer, destination string, workers int, benchmark, exportContext bool) error {
	m, err := selectHLSCodec(ctx, root, "alac", fetch)
	if err != nil {
		return err
	}
	cert, err := loadCertificate(certificatePath)
	if err != nil {
		return err
	}
	defer clear(cert)
	_, err = playback.Run(ctx, playback.Config{Runtime: cfg, Metadata: metadata, Manifest: m, AssetID: assetID, Protocol: client, Profile: profile, Session: session, Prepare: prepare, Certificate: cert, Destination: destination, Workers: workers, Benchmark: benchmark, ExportContext: exportContext, Progress: out})
	return err
}
func probeALACSPC(ctx context.Context, out io.Writer, cfg standalone.Config, stableID, certificatePath, root string, fetch func(context.Context, string) (*am.HLSManifest, error)) error {
	m, err := selectHLSCodec(ctx, root, "alac", fetch)
	if err != nil {
		return err
	}
	keys, err := playback.Keys(m)
	if err != nil {
		return err
	}
	cert, err := loadCertificate(certificatePath)
	if err != nil {
		return err
	}
	defer clear(cert)
	fmt.Fprintf(out, "ALAC SPC selection: segments=%d referencedKeys=%d certificateBytes=%d\n", len(m.Segments), len(keys), len(cert))
	for i, key := range keys {
		version, _ := strconv.ParseUint(key.Versions, 10, 32)
		p, err := standalone.NewPlaybackExchange(ctx, cfg, stableID)
		if err != nil {
			return err
		}
		spc, err := p.SPC(ctx, cert, key.URI, uint32(version))
		n := len(spc)
		clear(spc)
		err = errors.Join(err, p.Close())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "ALAC SPC: keyOrdinal=%d version=%d status=0 bytes=%d validatedExchange=true\n", i+1, version, n)
	}
	fmt.Fprintln(out, "ALAC SPC generation complete. No license request sent; audio remains encrypted.")
	return nil
}

func loadCertificate(path string) ([]byte, error) {
	if path == "" {
		return playback.PublicCertificate(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("public playback certificate unavailable")
	}
	cert, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	err = errors.Join(err, f.Close())
	if err != nil || len(cert) == 0 || len(cert) > 4<<20 {
		clear(cert)
		return nil, errors.New("invalid public playback certificate size")
	}
	return cert, nil
}
