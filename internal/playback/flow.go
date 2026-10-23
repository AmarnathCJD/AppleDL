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
	"strconv"
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
	Path                    string
	EncryptedPath           string
	ContextPath             string
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
	started := time.Now()
	result = &Result{}
	defer func() { result.TotalDuration = time.Since(started) }()
	var job *alacDecryptionJob
	if cfg.Destination != "" {
		job, err = prepareALACDecryption(ctx, cfg.Progress, cfg.Manifest, keys, cfg.Destination, cfg.Metadata, cfg.HTTPClient)
		if err != nil {
			return result, err
		}
		job.result = result
		job.exportContext = cfg.ExportContext
		result.EncryptedBytes = job.encryptedBytes
		result.SampleRate = job.init.Configuration.SampleRate
		result.BitDepth = job.init.Configuration.BitDepth
		result.Channels = job.init.Configuration.Channels
	}
	result.AcquisitionDuration = time.Since(started)
	cert := cfg.Certificate
	if len(cert) == 0 {
		cert = certificate
	}
	if len(cert) > 4<<20 {
		return result, errors.New("playback certificate exceeds size limit")
	}
	licenseStart := time.Now()
	var contexts []*standalone.PlaybackExchange
	defer func() {
		for _, p := range contexts {
			err = errors.Join(err, p.Close())
		}
	}()
	for i, key := range keys {
		version, _ := strconv.ParseUint(key.Versions, 10, 32)
		phase := time.Now()
		p, e := standalone.NewPlaybackExchange(ctx, cfg.Runtime, cfg.Metadata.StableID)
		result.LicenseRuntimeDuration += time.Since(phase)
		if e != nil {
			return result, e
		}
		contexts = append(contexts, p)
		phase = time.Now()
		spc, e := p.SPC(ctx, cert, key.URI, uint32(version))
		result.LicenseSPCDuration += time.Since(phase)
		if e != nil {
			return result, e
		}
		request := am.LicenseRequest{Protocol: "simplified", GUID: cfg.Metadata.StableID, AssetID: cfg.AssetID, KeyURI: key.URI, SPC: base64.StdEncoding.EncodeToString(spc)}
		clear(spc)
		phase = time.Now()
		var headers time.Duration
		prepare := func(ctx context.Context, plan am.PlaybackRequestPlan) (http.Header, error) {
			start := time.Now()
			h, err := cfg.Prepare(ctx, plan)
			headers += time.Since(start)
			return h, err
		}
		license, e := cfg.Protocol.FetchPlaybackLicense(ctx, cfg.Profile, cfg.Session, cfg.Metadata, request, prepare)
		result.LicenseHeadersDuration += headers
		result.LicenseExchangeDuration += time.Since(phase) - headers
		request.SPC = ""
		if e != nil {
			return result, e
		}
		if license.Status != 0 {
			code := license.Status
			license.Destroy()
			return result, fmt.Errorf("playback license status %d", code)
		}
		ckc, e := base64.StdEncoding.Strict().DecodeString(license.CKC)
		license.Destroy()
		if e != nil {
			clear(ckc)
			return result, errors.New("invalid CKC encoding")
		}
		phase = time.Now()
		e = p.LoadCKC(ctx, ckc)
		result.LicenseCKCDuration += time.Since(phase)
		clear(ckc)
		if e != nil {
			return result, e
		}
		fmt.Fprintf(cfg.Progress, "ALAC licensed context ready: keyOrdinal=%d\n", i+1)
	}
	result.LicenseDuration = time.Since(licenseStart)
	if job == nil {
		return result, nil
	}
	decryptStarted := time.Now()
	err = job.decrypt(ctx, cfg.Progress, contexts, cfg.Workers, cfg.Benchmark)
	result.DecryptionDuration = time.Since(decryptStarted)
	return result, err
}
