package standalone

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// PlaybackExchange owns one native SPC exchange in an isolated VM. Its serial
// comes from the existing local device identity; no Android state is read and
// no authentication identity is changed. SPC success alone does not establish
// that a license server will accept this standalone device.
type PlaybackExchange struct {
	gate              chan struct{}
	vm                *goVM
	exchange          uint64
	decryptContext    uint64
	ckcAttempted      bool
	contextReady      bool
	attempted, closed bool
}

func (*PlaybackExchange) String() string   { return "PlaybackExchange{redacted}" }
func (*PlaybackExchange) GoString() string { return "PlaybackExchange{redacted}" }

// PlaybackRuntimeStats exposes execution counts only, never native memory.
type PlaybackRuntimeStats struct{ WorkerThreads, SleepCalls int }

func (p *PlaybackExchange) RuntimeStats() PlaybackRuntimeStats {
	p.gate <- struct{}{}
	defer func() { <-p.gate }()
	return PlaybackRuntimeStats{WorkerThreads: len(p.vm.threads) - 1, SleepCalls: p.vm.imports["sleep"]}
}

func NewPlaybackExchange(ctx context.Context, cfg Config, stableID string) (p *PlaybackExchange, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := hex.DecodeString(stableID)
	if err != nil || len(id) != 8 {
		return nil, errors.New("playback requires the local device identity")
	}
	clear(id)
	v, err := newGoVM()
	if err != nil {
		return nil, err
	}
	p = &PlaybackExchange{gate: make(chan struct{}, 1), vm: v}
	defer func() {
		if recover() != nil {
			err = errors.New("initialize playback runtime failed")
		}
		if err != nil {
			err = errors.Join(err, p.Close())
			p = nil
		}
	}()
	// Empty serial properties cause native SPC status -42676. Populate a
	// stable local serial in this playback VM only.
	v.systemProperties = map[string]string{"ro.serialno": strings.ToLower(stableID)}
	v.instructionLimit = 200_000_000
	first := len(v.constructors)
	if err = v.loadGoImage("libCoreLSKD.so", 0x40000000); err != nil {
		return p, err
	}
	for _, address := range v.constructors[first:] {
		if _, err = v.callAddress(ctx, address); err != nil {
			return p, err
		}
	}
	return p, nil
}

func (p *PlaybackExchange) invoke(ctx context.Context, name string, args ...uint64) error {
	code, err := p.vm.call(ctx, name, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return &StatusError{Operation: name, Code: code}
	}
	return nil
}

func (p *PlaybackExchange) run(ctx context.Context, fn func() error) (err error) {
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-p.gate }()
	if p.closed {
		return errors.New("playback exchange is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.vm.failure != nil {
		return p.vm.failure
	}
	defer func() {
		if recover() != nil {
			p.vm.failure = errors.New("native playback operation failed")
			err = p.vm.failure
		}
	}()
	return fn()
}

// SPC uses the original HLS key URI and a certificate-derived movie ID. It is
// single-use even on native failure. The caller owns the returned buffer and
// should clear it after the license request. The exchange stays alive until
// Close; its native output allocation is released before this method returns.
func (p *PlaybackExchange) SPC(ctx context.Context, certificate []byte, keyURI string, version uint32) (spc []byte, err error) {
	if len(certificate) == 0 || len(certificate) > bufferLimit || len(keyURI) <= len("skd://") || len(keyURI) > 65536 || !strings.HasPrefix(keyURI, "skd://") || strings.ContainsRune(keyURI, 0) || version == 0 {
		return nil, errors.New("invalid playback certificate, key URI or version")
	}
	err = p.run(ctx, func() (err error) {
		if p.attempted {
			return errors.New("SPC already attempted; create a new exchange")
		}
		p.attempted = true
		v := p.vm
		cert, uri, slots := v.data(certificate), v.string(keyURI), v.alloc(40)
		defer v.free(cert)
		defer v.free(uri)
		defer v.free(slots)
		v.write(slots, binary.LittleEndian.AppendUint32(nil, version))
		if err = p.invoke(ctx, "Qhl17oSYJtCJIxM", cert, uint64(len(certificate)), slots, 1, slots+8); err != nil {
			return err
		}
		movieID := binary.LittleEndian.Uint64(v.read(slots+8, 8))
		if movieID == 0 {
			return errors.New("playback movie ID missing")
		}
		callErr := p.invoke(ctx, "sWBoEyhXQd6FTiLw", movieID, cert, uint64(len(certificate)), uri, uint64(len(keyURI)), slots+16, slots+24, slots+32)
		ptr := binary.LittleEndian.Uint64(v.read(slots+16, 8))
		n := binary.LittleEndian.Uint32(v.read(slots+24, 4))
		p.exchange = binary.LittleEndian.Uint64(v.read(slots+32, 8))
		if ptr != 0 {
			defer func() { err = errors.Join(err, p.invoke(context.Background(), "Ud5PNQt99i", ptr)) }()
		}
		if callErr != nil {
			return callErr
		}
		if ptr == 0 || n == 0 || n > bufferLimit || p.exchange == 0 {
			return errors.New("invalid native SPC output")
		}
		if err := p.invoke(ctx, "PqUfoAiCUu", p.exchange); err != nil {
			return err
		}
		spc = v.read(ptr, uint64(n))
		return nil
	})
	if err != nil {
		clear(spc)
		spc = nil
	}
	return
}

func (p *PlaybackExchange) Close() (err error) {
	p.gate <- struct{}{}
	defer func() { <-p.gate }()
	if p.closed {
		return nil
	}
	p.closed = true
	defer p.vm.close()
	defer func() {
		p.exchange = 0
		p.decryptContext = 0
		p.contextReady = false
		clear(p.vm.systemProperties)
		if recover() != nil {
			err = errors.New("close playback exchange failed")
		}
	}()
	if p.decryptContext != 0 && p.vm.failure == nil {
		// SVFootHillPContext's shared_ptr disposal (0x00420984) calls
		// N8pdwAfn with the context value, before deleting its pointer slot.
		_, err = p.vm.call(context.Background(), "N8pdwAfn", p.decryptContext)
	}
	if p.exchange != 0 && p.vm.failure == nil {
		err = errors.Join(err, p.invoke(context.Background(), "JE2f6WCx", p.exchange))
	}
	return
}

// LoadCKC accepts decoded opaque license bytes for this exact SPC exchange.
// It follows SVFootHillPContext: can-process, validate exchange, process CKC,
// validate context. One attempt is allowed; no raw key is returned to Go.
func (p *PlaybackExchange) LoadCKC(ctx context.Context, ckc []byte) error {
	if len(ckc) == 0 || len(ckc) > bufferLimit {
		return errors.New("invalid CKC size")
	}
	return p.run(ctx, func() error {
		if p.exchange == 0 || p.ckcAttempted {
			return errors.New("CKC requires an unused valid SPC exchange")
		}
		p.ckcAttempted = true
		if err := p.invoke(ctx, "ZZUDP2EEn9tLDQ"); err != nil {
			return err
		}
		if err := p.invoke(ctx, "PqUfoAiCUu", p.exchange); err != nil {
			return err
		}
		v := p.vm
		input, out := v.data(ckc), v.alloc(8)
		defer v.free(input)
		defer v.free(out)
		err := p.invoke(ctx, "C956s6fM", p.exchange, input, uint64(len(ckc)), out)
		p.decryptContext = binary.LittleEndian.Uint64(v.read(out, 8))
		if err != nil {
			return err
		}
		if p.decryptContext == 0 {
			return errors.New("native license context missing")
		}
		if err := p.invoke(ctx, "jSNXSLgDwR", p.decryptContext); err != nil {
			return err
		}
		p.contextReady = true
		return nil
	})
}

// DecryptALACSample ports SVPastisDecryptor's type-7/mode-5 in-place call. The
// caller must pass one demuxed ALAC access unit, never an MP4 container or mdat.
func (p *PlaybackExchange) DecryptALACSample(ctx context.Context, sample []byte) (result []byte, err error) {
	if len(sample) == 0 || len(sample) > bufferLimit {
		return nil, errors.New("invalid ALAC sample size")
	}
	err = p.run(ctx, func() error {
		if !p.contextReady || p.decryptContext == 0 {
			return errors.New("ALAC decryption requires a loaded license")
		}
		v := p.vm
		buf := v.data(sample)
		defer v.free(buf)
		if err := p.invoke(ctx, "NfcRKVnxuKZy04KWbdFu71Ou", p.decryptContext, 5, buf, buf, uint64(len(sample))); err != nil {
			return err
		}
		result = v.read(buf, uint64(len(sample)))
		return nil
	})
	if err != nil {
		clear(result)
		result = nil
	}
	return
}
