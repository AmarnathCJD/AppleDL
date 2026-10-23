package playback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/internal/envelope"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

const bundleLimit = 48 << 20

type bundlePart struct {
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Context int    `json:"context"` // -1 for the initialization, otherwise zero based
}
type bundleLayout struct {
	Version int          `json:"version"`
	Size    int64        `json:"size"`
	SHA256  string       `json:"sha256"`
	Parts   []bundlePart `json:"parts"`
}
type contextBundle struct {
	Layout   bundleLayout `json:"layout"`
	Contexts [][]byte     `json:"contexts"`
}

func (b *contextBundle) destroy() {
	for _, c := range b.Contexts {
		clear(c)
	}
	*b = contextBundle{}
}
func (b *contextBundle) String() string   { return "contextBundle{redacted}" }
func (b *contextBundle) GoString() string { return b.String() }

func contextBinding(layout bundleLayout, ordinal int) [32]byte {
	data, _ := json.Marshal(struct {
		Layout  bundleLayout
		Ordinal int
	}{layout, ordinal})
	return sha256.Sum256(data)
}

func validBundle(b *contextBundle) bool {
	if b.Layout.Version != 1 || b.Layout.Size <= 0 || len(b.Layout.Parts) < 2 || len(b.Layout.Parts) > 100001 || len(b.Contexts) == 0 || len(b.Contexts) > 32 {
		return false
	}
	validHash := func(s string) bool {
		x, e := hex.DecodeString(s)
		return e == nil && len(x) == 32 && hex.EncodeToString(x) == s
	}
	if !validHash(b.Layout.SHA256) {
		return false
	}
	var size int64
	used := make([]bool, len(b.Contexts))
	for i, p := range b.Layout.Parts {
		if p.Size < 1 || p.Size > am.MaxHLSResourceBytes || !validHash(p.SHA256) {
			return false
		}
		if i == 0 {
			if p.Context != -1 {
				return false
			}
		} else {
			if p.Context < 0 || p.Context >= len(b.Contexts) {
				return false
			}
			used[p.Context] = true
		}
		size += p.Size
	}
	for i, c := range b.Contexts {
		if !used[i] || len(c) == 0 || len(c) > 24<<20 {
			return false
		}
	}
	return size == b.Layout.Size
}

func (j *alacDecryptionJob) exportBundle(ctx context.Context, contexts []*standalone.ALACGoDecryptor) (err error) {
	path := filepath.Join(j.destination, "encrypted-alac.m4a")
	licensePath := filepath.Join(j.destination, "license-context.amctx")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot create encrypted bundle file")
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	b := contextBundle{Layout: bundleLayout{Version: 1}}
	defer b.destroy()
	h := sha256.New()
	files := append([]am.HLSAcquiredFile{j.initialFile}, j.segments...)
	for i, part := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, e := j.read(part)
		if e != nil {
			return e
		}
		_, e = io.MultiWriter(f, h).Write(data)
		clear(data)
		if e != nil {
			return errors.New("cannot write encrypted bundle file")
		}
		ordinal := -1
		if i > 0 {
			ordinal = j.keyForSegment[i-1]
		}
		b.Layout.Parts = append(b.Layout.Parts, bundlePart{part.Size, part.SHA256, ordinal})
		b.Layout.Size += part.Size
	}
	b.Layout.SHA256 = hex.EncodeToString(h.Sum(nil))
	for i, c := range contexts {
		if c == nil {
			return errors.New("cannot export unused or missing context")
		}
		blob, e := c.ExportContext(ctx, contextBinding(b.Layout, i))
		if e != nil {
			return e
		}
		b.Contexts = append(b.Contexts, blob)
	}
	if !validBundle(&b) {
		return errors.New("invalid context bundle")
	}
	plain, err := json.Marshal(&b)
	defer clear(plain)
	if err != nil {
		return errors.New("cannot encode context bundle")
	}
	blob, err := envelope.Encode("AMBND001", plain, bundleLimit)
	defer clear(blob)
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	lf, err := os.OpenFile(licensePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create context bundle")
	}
	_, err = lf.Write(blob)
	if err == nil {
		err = lf.Sync()
	}
	err = errors.Join(err, lf.Close())
	if err != nil {
		_ = os.Remove(licensePath)
		return errors.New("cannot save context bundle")
	}
	j.result.EncryptedPath, j.result.ContextPath = path, licensePath
	return nil
}

// DecryptBundle verifies the exact ciphertext and restores its matching Go
// contexts. It uses no network, account state, native code or license service.
// Both input files are private. Output must be a new file.
func DecryptBundle(ctx context.Context, ciphertext, bundle, output string, workers int, progress io.Writer) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if workers < 0 || workers > 64 {
		return nil, errors.New("workers must be 0 through 64")
	}
	if workers == 0 {
		workers = min(16, runtime.GOMAXPROCS(0))
	}
	if progress == nil {
		progress = io.Discard
	}
	if output == "" {
		return nil, errors.New("output path required")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		return nil, errors.New("output must be a new file")
	}
	started := time.Now()
	f, err := os.Open(bundle)
	if err != nil {
		return nil, errors.New("cannot open context bundle")
	}
	raw, err := io.ReadAll(io.LimitReader(f, bundleLimit+1))
	err = errors.Join(err, f.Close())
	defer clear(raw)
	if err != nil {
		return nil, errors.New("cannot read context bundle")
	}
	plain, err := envelope.Decode("AMBND001", raw, bundleLimit)
	defer clear(plain)
	if err != nil {
		return nil, err
	}
	var b contextBundle
	defer b.destroy()
	if json.Unmarshal(plain, &b) != nil || !validBundle(&b) {
		return nil, errors.New("invalid context bundle layout")
	}
	source, err := os.Open(ciphertext)
	if err != nil {
		return nil, errors.New("cannot open ciphertext")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != b.Layout.Size {
		return nil, errors.New("ciphertext size mismatch")
	}
	j := &alacDecryptionJob{result: &Result{}, source: source, offsets: map[string]int64{}}
	h := sha256.New()
	var offset int64
	var timeline uint64
	association := map[uint32]int{}
	for i, part := range b.Layout.Parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		receipt := am.HLSAcquiredFile{Name: fmt.Sprintf("part-%06d", i), Size: part.Size, SHA256: part.SHA256}
		j.offsets[receipt.Name] = offset
		offset += part.Size
		data, e := j.read(receipt)
		if e != nil {
			return nil, e
		}
		h.Write(data)
		if i == 0 {
			j.init, e = am.ParseALACInitialization(data)
		} else {
			var fragment *am.ALACFragment
			fragment, e = am.ParseALACFragment(data, j.init)
			if e == nil {
				if fragment.DecodeTime != timeline {
					e = errors.New("bundle sample timeline mismatch")
				}
				if previous, ok := association[fragment.DescriptionIndex]; ok && previous != part.Context {
					e = errors.New("bundle description context mismatch")
				}
				association[fragment.DescriptionIndex] = part.Context
				timeline += fragment.Duration
			}
			j.segments = append(j.segments, receipt)
			j.keyForSegment = append(j.keyForSegment, part.Context)
		}
		clear(data)
		if e != nil {
			return nil, e
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != b.Layout.SHA256 {
		return nil, errors.New("ciphertext checksum mismatch")
	}
	var contexts []*standalone.ALACGoDecryptor
	defer func() {
		for _, c := range contexts {
			c.Close()
		}
	}()
	for i, blob := range b.Contexts {
		c, e := standalone.ImportALACGoDecryptor(ctx, blob, contextBinding(b.Layout, i))
		if e != nil {
			return nil, e
		}
		contexts = append(contexts, c)
	}
	j.result.SetupDuration = time.Since(started)
	if err := j.decryptWithWorkers(ctx, progress, contexts, workers, output); err != nil {
		return nil, err
	}
	j.result.EncryptedBytes = b.Layout.Size
	j.result.SampleRate = j.init.Configuration.SampleRate
	j.result.BitDepth = j.init.Configuration.BitDepth
	j.result.Channels = j.init.Configuration.Channels
	j.result.TotalDuration = time.Since(started)
	j.result.DecryptionDuration = j.result.TotalDuration
	return j.result, nil
}
