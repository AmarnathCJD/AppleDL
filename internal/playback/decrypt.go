package playback

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

type alacDecryptionJob struct {
	result         *Result
	initialFile    am.HLSAcquiredFile
	exportContext  bool
	source         *os.File
	offsets        map[string]int64
	encryptedBytes int64
	destination    string
	init           *am.ALACInitialization
	segments       []am.HLSAcquiredFile
	keyForSegment  []int
}

func alacSegmentKeys(m *am.HLSManifest, keys []am.HLSKey) ([]int, error) {
	if m == nil || len(m.Maps) != 1 || len(m.Segments) == 0 {
		return nil, errors.New("ALAC decryption requires one initialization map")
	}
	var selectedKeys []int
	for _, s := range m.Segments {
		if s.MapIndex == nil || *s.MapIndex != 0 || s.DiscontinuitySequence != m.Segments[0].DiscontinuitySequence {
			return nil, errors.New("unsupported ALAC segment association")
		}
		k, err := appleSegmentKey(m, s)
		if err != nil {
			return nil, err
		}
		if k.Versions == "" {
			k.Versions = "1"
		}
		selected := -1
		for i, key := range keys {
			if key.URI == k.URI && key.Versions == k.Versions {
				selected = i
				break
			}
		}
		if selected < 0 {
			return nil, errors.New("ALAC segment has no licensed key declaration")
		}
		selectedKeys = append(selectedKeys, selected)
	}
	return selectedKeys, nil
}

// Acquisition and licensing use the same in-memory playlist. Old ciphertext is
// not associated with newly obtained licenses based on filenames or song titles.
func prepareALACDecryption(ctx context.Context, out io.Writer, m *am.HLSManifest, keys []am.HLSKey, destination string, metadata am.DeviceMetadata, httpClient *http.Client) (*alacDecryptionJob, error) {
	selectedKeys, err := alacSegmentKeys(m, keys)
	if err != nil {
		return nil, err
	}
	j := &alacDecryptionJob{destination: destination, keyForSegment: selectedKeys}
	var session [16]byte
	if _, err := rand.Read(session[:]); err != nil {
		return nil, errors.New("cannot generate playback session ID")
	}
	session[6] = (session[6] & 15) | 0x40
	session[8] = (session[8] & 63) | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", session[:4], session[4:6], session[6:8], session[8:10], session[10:])
	if err := os.Mkdir(destination, 0700); err != nil {
		return nil, errors.New("cannot create ALAC destination")
	}
	fmt.Fprintln(out, "Acquiring fresh ALAC initialization and encrypted fragments for the selected licenses.")
	receipt, err := am.AcquireHLS(ctx, httpClient, m, filepath.Join(destination, "encrypted"), am.HLSAcquisitionOptions{UserAgent: metadata.UserAgent, Language: metadata.Language, PlaybackSessionID: id})
	if err != nil {
		return nil, err
	}
	j.encryptedBytes = receipt.TotalBytes
	var nextTime uint64
	var samples int
	descriptionKeys := map[uint32]int{}
	for _, f := range receipt.Files {
		data, err := j.read(f)
		if err != nil {
			return nil, err
		}
		if f.Initialization {
			if j.init != nil {
				clear(data)
				return nil, errors.New("multiple ALAC initialization files")
			}
			j.initialFile = f
			j.init, err = am.ParseALACInitialization(data)
		} else {
			var fragment *am.ALACFragment
			fragment, err = am.ParseALACFragment(data, j.init)
			if err == nil {
				if f.SegmentIndex != len(j.segments) || fragment.DecodeTime != nextTime {
					clear(data)
					return nil, errors.New("ALAC sample timeline mismatch")
				}
				key := j.keyForSegment[f.SegmentIndex]
				if previous, ok := descriptionKeys[fragment.DescriptionIndex]; ok && previous != key {
					clear(data)
					return nil, errors.New("ALAC description changed license association")
				}
				descriptionKeys[fragment.DescriptionIndex] = key
				nextTime += fragment.Duration
				samples += len(fragment.Samples)
				j.segments = append(j.segments, f)
			}
		}
		clear(data)
		if err != nil {
			return nil, err
		}
	}
	if j.init == nil || len(j.segments) != len(m.Segments) {
		return nil, errors.New("incomplete ALAC sample acquisition")
	}
	fmt.Fprintf(out, "ALAC demux validated: segments=%d samples=%d rate=%d bitDepth=%d channels=%d descriptions=%d bytes=%d\n", len(j.segments), samples, j.init.Configuration.SampleRate, j.init.Configuration.BitDepth, j.init.Configuration.Channels, j.init.DescriptionCount, receipt.TotalBytes)
	return j, nil
}

func (j *alacDecryptionJob) read(f am.HLSAcquiredFile) ([]byte, error) {
	if f.Name == "" || filepath.Base(f.Name) != f.Name || f.Size < 1 || f.Size > am.MaxHLSResourceBytes {
		return nil, errors.New("invalid acquired ALAC file")
	}
	var data []byte
	var err, closeErr error
	if j.source != nil {
		offset, ok := j.offsets[f.Name]
		if !ok {
			return nil, errors.New("missing bundled ALAC part")
		}
		data, err = io.ReadAll(io.NewSectionReader(j.source, offset, f.Size))
	} else {
		file, e := os.Open(filepath.Join(j.destination, "encrypted", f.Name))
		if e != nil {
			return nil, errors.New("cannot open acquired ALAC file")
		}
		data, err = io.ReadAll(io.LimitReader(file, f.Size+1))
		closeErr = file.Close()
	}
	digest := sha256.Sum256(data)
	if err != nil || closeErr != nil || int64(len(data)) != f.Size || hex.EncodeToString(digest[:]) != f.SHA256 {
		clear(data)
		return nil, errors.New("acquired ALAC file integrity mismatch")
	}
	return data, nil
}

func (j *alacDecryptionJob) decrypt(ctx context.Context, out io.Writer, contexts []*standalone.PlaybackExchange, workers int, benchmark bool) (err error) {
	goContexts := make([]*standalone.ALACGoDecryptor, len(contexts))
	defer func() {
		for _, d := range goContexts {
			if d != nil {
				d.Close()
			}
		}
	}()
	for i, f := range j.segments {
		key := j.keyForSegment[i]
		if key < 0 || key >= len(contexts) || contexts[key] == nil {
			return errors.New("ALAC license context is missing")
		}
		if goContexts[key] != nil {
			continue
		}
		data, e := j.read(f)
		if e != nil {
			return e
		}
		fragment, e := am.ParseALACFragment(data, j.init)
		if e != nil {
			clear(data)
			return e
		}
		if len(fragment.Samples) == 0 {
			clear(data)
			return errors.New("ALAC setup sample is missing")
		}
		s := fragment.Samples[0]
		goContexts[key], e = contexts[key].NewALACGoDecryptor(ctx, data[s.Offset:s.Offset+int(s.Size)])
		clear(data)
		if e != nil {
			return fmt.Errorf("ALAC Go initialization: %w", e)
		}
		stats := goContexts[key].Stats()
		j.result.SetupDuration += stats.SetupElapsed
		fmt.Fprintf(out, "ALAC Go initialization: keyOrdinal=%d outputParity=true registerParity=true setup=%s\n", key+1, stats.SetupElapsed)
	}
	// The full-song pass deliberately runs after destroying all playback VMs.
	// Licensing/setup has completed; only detached Go state remains.
	for _, p := range contexts {
		if p != nil {
			if e := p.Close(); e != nil {
				return e
			}
		}
	}
	fmt.Fprintln(out, "ALAC Go data path ready: all playback setup runtimes closed.")
	if workers == 0 {
		workers = min(16, runtime.GOMAXPROCS(0))
	}
	if workers < 1 || workers > 64 {
		return errors.New("ALAC workers must be between 1 and 64")
	}
	if j.exportContext {
		if err := j.exportBundle(ctx, goContexts); err != nil {
			return err
		}
	}
	if benchmark {
		fmt.Fprintf(out, "ALAC benchmark: logicalCPUs=%d GOMAXPROCS=%d; three passes per worker count\n", runtime.NumCPU(), runtime.GOMAXPROCS(0))
		for pass, count := range []int{8, 12, 16, 20, 24, 32, 32, 24, 20, 16, 12, 8, 16, 24, 12, 32, 8, 20} {
			// Release earlier benchmark worker copies outside the measured pass.
			runtime.GC()
			path := filepath.Join(j.destination, fmt.Sprintf("benchmark-%02d-workers-%d.m4a", pass+1, count))
			if err := j.decryptWithWorkers(ctx, out, goContexts, count, path); err != nil {
				return err
			}
		}
	}
	return j.decryptWithWorkers(ctx, out, goContexts, workers, filepath.Join(j.destination, "decrypted-fragmented.m4a"))
}

func (j *alacDecryptionJob) decryptWithWorkers(ctx context.Context, out io.Writer, sources []*standalone.ALACGoDecryptor, workers int, path string) (err error) {
	cloneStarted := time.Now()
	var clones []*standalone.ALACGoDecryptor
	defer func() {
		for _, d := range clones {
			d.Close()
		}
	}()
	decryptors := make([][]func(context.Context, []byte) ([]byte, error), len(sources))
	for key, source := range sources {
		if source == nil {
			continue
		}
		for range workers {
			d, err := source.Clone(ctx)
			if err != nil {
				return err
			}
			clones = append(clones, d)
			decryptors[key] = append(decryptors[key], d.DecryptALACSample)
		}
	}
	j.result.CloneDuration = time.Since(cloneStarted)
	fmt.Fprintf(out, "ALAC worker cloning: workers=%d wall=%s\n", workers, j.result.CloneDuration)
	started := time.Now()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create new ALAC output")
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	init := j.init.ClearInitialization()
	_, err = file.Write(init)
	clear(init)
	if err != nil {
		return errors.New("cannot write ALAC initialization")
	}
	samples := 0
	for i, f := range j.segments {
		key := j.keyForSegment[i]
		if key < 0 || key >= len(decryptors) {
			return errors.New("ALAC license context is missing")
		}
		data, e := j.read(f)
		if e != nil {
			return e
		}
		plain, fragment, e := am.DecryptALACFragmentParallel(ctx, data, j.init, decryptors[key]...)
		clear(data)
		if e != nil {
			clear(plain)
			return fmt.Errorf("ALAC segment %d: %w", i+1, e)
		}
		_, e = file.Write(plain)
		clear(plain)
		if e != nil {
			return errors.New("cannot write ALAC fragment")
		}
		samples += len(fragment.Samples)
		fmt.Fprintf(out, "ALAC Go decryption: segment=%d/%d samples=%d keyOrdinal=%d status=0\n", i+1, len(j.segments), samples, key+1)
	}
	if err = file.Sync(); err != nil {
		return errors.New("cannot finish ALAC output")
	}
	var goTime time.Duration
	for _, d := range clones {
		if d != nil {
			goTime += d.Stats().Elapsed
		}
	}
	j.result.Path, j.result.Workers, j.result.Samples = path, workers, samples
	j.result.SampleDuration = time.Since(started)
	fmt.Fprintf(out, "ALAC Go decryption completed: workers=%d samples=%d aggregateWorkerTime=%s wall=%s. Output requires independent decode validation.\n", workers, samples, goTime, j.result.SampleDuration)
	return nil
}
