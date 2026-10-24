// Package playback shares acquisition, licensing and ALAC decryption between
// the diagnostic command and the high-level client.
package playback

import (
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

// Public playback certificate observed in Android build 1606; no private key.
//
//go:embed certificate.bin
var certificate []byte

// PublicCertificate returns a private copy of the embedded public certificate.
func PublicCertificate() []byte { return append([]byte(nil), certificate...) }

type Config struct {
	Runtime       standalone.Config
	Metadata      am.DeviceMetadata
	Manifest      *am.HLSManifest
	AssetID       string
	Protocol      *am.Client
	Profile       *am.PlaybackProfile
	Session       *am.PlaybackSession
	Prepare       am.PlaybackRequestPreparer
	HTTPClient    *http.Client
	Certificate   []byte
	Destination   string
	Workers       int
	Benchmark     bool
	ExportContext bool
	Progress      io.Writer
}

type Result struct {
	Path           string
	EncryptedPath  string
	ContextPath    string
	Workers        int
	Samples        int
	SampleRate     uint32
	BitDepth       uint8
	Channels       uint8
	EncryptedBytes int64
	// Acquisition and licensing overlap; these durations must not be added.
	AcquisitionDuration time.Duration
	LicenseDuration     time.Duration
	// Component durations sum work across keys, which may run concurrently.
	// LicenseDuration measures wall time, rather than the sum of these fields.
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

func Run(ctx context.Context, cfg Config) (result *Result, err error) {
	if cfg.Workers < 0 || cfg.Workers > 64 {
		return nil, errors.New("workers must be 0 through 64")
	}
	if cfg.Progress == nil {
		cfg.Progress = io.Discard
	}
	if cfg.Protocol == nil || cfg.Profile == nil || cfg.Session == nil || cfg.Prepare == nil {
		return nil, errors.New("playback session and protocol configuration required")
	}
	keys, err := alacPlaybackKeys(cfg.Manifest)
	if err != nil {
		return nil, err
	}
	if cfg.Destination != "" {
		if _, err := alacSegmentKeys(cfg.Manifest, keys); err != nil {
			return nil, err
		}
	}
	cert := cfg.Certificate
	if len(cert) == 0 {
		cert = certificate
	}
	if len(cert) > 4<<20 {
		return nil, errors.New("playback certificate exceeds size limit")
	}
	started := time.Now()
	result = &Result{}
	defer func() { result.TotalDuration = time.Since(started) }()
	var job *alacDecryptionJob
	acquire := func(ctx context.Context) error {
		phase := time.Now()
		defer func() { result.AcquisitionDuration = time.Since(phase) }()
		if cfg.Destination == "" {
			return nil
		}
		var e error
		job, e = prepareALACDecryption(ctx, cfg.Progress, cfg.Manifest, keys, cfg.Destination, cfg.Metadata, cfg.HTTPClient)
		if e != nil {
			return e
		}
		job.result = result
		job.exportContext = cfg.ExportContext
		result.EncryptedBytes = job.encryptedBytes
		result.SampleRate = job.init.Configuration.SampleRate
		result.BitDepth = job.init.Configuration.BitDepth
		result.Channels = job.init.Configuration.Channels
		return nil
	}
	contexts := make([]*standalone.PlaybackExchange, len(keys))
	defer func() {
		for _, p := range contexts {
			if p != nil {
				err = errors.Join(err, p.Close())
			}
		}
	}()
	// Each key has private runtime state. Keep account requests and caller-supplied
	// header preparation serial; overlap the expensive local SPC/CKC calculations.
	requestGate := make(chan struct{}, 1)
	timings := make([]Result, len(keys))
	license := func(ctx context.Context) error {
		phase := time.Now()
		defer func() { result.LicenseDuration = time.Since(phase) }()
		return runParallel(ctx, len(keys), min(2, runtime.GOMAXPROCS(0)), func(ctx context.Context, i int) error {
			key := keys[i]
			result := &timings[i]
			version, _ := strconv.ParseUint(key.Versions, 10, 32)
			phase := time.Now()
			p, e := standalone.NewPlaybackExchange(ctx, cfg.Runtime, cfg.Metadata.StableID)
			result.LicenseRuntimeDuration += time.Since(phase)
			if e != nil {
				return e
			}
			contexts[i] = p
			phase = time.Now()
			spc, e := p.SPC(ctx, cert, key.URI, uint32(version))
			result.LicenseSPCDuration += time.Since(phase)
			if e != nil {
				return e
			}
			request := am.LicenseRequest{Protocol: "simplified", GUID: cfg.Metadata.StableID, AssetID: cfg.AssetID, KeyURI: key.URI, SPC: base64.StdEncoding.EncodeToString(spc)}
			clear(spc)
			var headers time.Duration
			prepare := func(ctx context.Context, plan am.PlaybackRequestPlan) (http.Header, error) {
				start := time.Now()
				h, err := cfg.Prepare(ctx, plan)
				headers += time.Since(start)
				return h, err
			}
			select {
			case requestGate <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			phase = time.Now()
			license, e := cfg.Protocol.FetchPlaybackLicense(ctx, cfg.Profile, cfg.Session, cfg.Metadata, request, prepare)
			<-requestGate
			result.LicenseHeadersDuration += headers
			result.LicenseExchangeDuration += time.Since(phase) - headers
			request.SPC = ""
			if e != nil {
				return e
			}
			if license.Status != 0 {
				code := license.Status
				license.Destroy()
				return fmt.Errorf("playback license status %d", code)
			}
			ckc, e := base64.StdEncoding.Strict().DecodeString(license.CKC)
			license.Destroy()
			if e != nil {
				clear(ckc)
				return errors.New("invalid CKC encoding")
			}
			phase = time.Now()
			e = p.LoadCKC(ctx, ckc)
			result.LicenseCKCDuration += time.Since(phase)
			clear(ckc)
			if e != nil {
				return e
			}
			return nil
		})
	}
	// Acquisition and licensing depend only on the validated playlist. Join both
	// before decryption or cleanup; either failure cancels the other operation.
	err = runParallel(ctx, 2, 2, func(ctx context.Context, i int) error {
		if i == 0 {
			return acquire(ctx)
		}
		return license(ctx)
	})
	for i, timing := range timings {
		result.LicenseRuntimeDuration += timing.LicenseRuntimeDuration
		result.LicenseSPCDuration += timing.LicenseSPCDuration
		result.LicenseHeadersDuration += timing.LicenseHeadersDuration
		result.LicenseExchangeDuration += timing.LicenseExchangeDuration
		result.LicenseCKCDuration += timing.LicenseCKCDuration
		if err == nil {
			fmt.Fprintf(cfg.Progress, "ALAC licensed context ready: keyOrdinal=%d\n", i+1)
		}
	}
	if err != nil {
		return result, err
	}
	if job == nil {
		return result, nil
	}
	decryptStarted := time.Now()
	err = job.decrypt(ctx, cfg.Progress, contexts, cfg.Workers, cfg.Benchmark)
	result.DecryptionDuration = time.Since(decryptStarted)
	return result, err
}

// runParallel joins every started operation before returning, including on
// failure, so the caller can safely close all partially prepared contexts.
func runParallel(ctx context.Context, count, workers int, work func(context.Context, int) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var group sync.WaitGroup
	jobs := make(chan int)
	for range min(count, max(1, workers)) {
		group.Go(func() {
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := work(ctx, i); err != nil {
					cancel(err)
					return
				}
			}
		})
	}
dispatch:
	for i := range count {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	group.Wait()
	return context.Cause(ctx)
}
