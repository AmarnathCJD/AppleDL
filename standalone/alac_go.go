package standalone

import (
	"bytes"
	"context"
	"errors"
	"time"
)

// ALACGoDecryptor runs the APK's compiled block arithmetic in Go. The licensed
// runtime and a verified sample initialize its private tables. The default
// runtime also executes in Go. After construction it owns no VM. It may outlive
// the PlaybackExchange that created it. Close releases its private setup state.
// The translation is pinned to the library hash checked by NewPlaybackExchange.
type ALACGoDecryptor struct {
	gate  chan struct{}
	loop  *alacLoopCapture
	stats ALACGoStats
}

func (*ALACGoDecryptor) String() string   { return "ALACGoDecryptor{redacted}" }
func (*ALACGoDecryptor) GoString() string { return "ALACGoDecryptor{redacted}" }

// ALACGoStats contains timings/counts only. SetupElapsed includes one complete
// runtime sample and its compiled-loop parity checks. Elapsed measures Go calls.
type ALACGoStats struct {
	SetupElapsed time.Duration
	Elapsed      time.Duration
	Samples      int
	Bytes        uint64
	SetupPages   int
}

// NewALACGoDecryptor initializes reusable tables for this licensed context.
// firstSample must be a complete encrypted access unit belonging to the context.
// Initialization requires exact runtime/compiled-loop output and register parity.
func (p *PlaybackExchange) NewALACGoDecryptor(ctx context.Context, firstSample []byte) (d *ALACGoDecryptor, err error) {
	if len(firstSample) < 16 || uint64(len(firstSample)) > alacLoopCapacity {
		return nil, errors.New("Go ALAC initialization sample size")
	}
	err = p.run(ctx, func() error {
		if !p.contextReady || p.decryptContext == 0 {
			return errors.New("Go ALAC requires a loaded license")
		}
		start := time.Now()
		v := p.vm
		buffer := v.alloc(alacLoopCapacity)
		defer v.free(buffer)
		v.write(buffer, firstSample)
		c := &alacLoopCapture{vm: v, ctx: ctx, buffer: buffer, size: len(firstSample)}
		transferred := false
		defer func() {
			if !transferred {
				c.close()
			}
		}()
		remove, err := v.installALACCapture(c)
		if err != nil {
			return err
		}
		defer remove()
		err = p.invoke(ctx, "NfcRKVnxuKZy04KWbdFu71Ou", p.decryptContext, 5, buffer, buffer, uint64(len(firstSample)))
		if e := remove(); e != nil {
			return e
		}
		if c.err != nil {
			return c.err
		}
		if err != nil {
			return err
		}
		if !c.entered || !c.ended {
			return errors.New("Go ALAC loop boundary missing")
		}
		plain := v.read(buffer, uint64(len(firstSample)))
		defer clear(plain)
		if !bytes.Equal(plain, c.first) || !c.registerParity {
			return errors.New("Go ALAC initialization parity mismatch")
		}
		// Permanently detach the setup runtime. Recheck the complete sample
		// with all reads from the runtime disabled.
		c.memory.read = nil
		c.vm, c.ctx = nil, nil
		candidate, _, err := c.replay(ctx, firstSample, len(firstSample))
		defer clear(candidate)
		if err != nil {
			return err
		}
		if !bytes.Equal(candidate, plain) {
			return errors.New("Go ALAC detached parity mismatch")
		}
		clear(c.first)
		c.first = nil
		c.endState = alacLoopState{}
		c.memory.reset()
		d = &ALACGoDecryptor{gate: make(chan struct{}, 1), loop: c,
			stats: ALACGoStats{SetupElapsed: time.Since(start), SetupPages: len(c.memory.initial)}}
		transferred = true
		return nil
	})
	if err != nil && d != nil {
		d.Close()
		d = nil
	}
	return
}

func (v *goVM) installALACCapture(c *alacLoopCapture) (func() error, error) {
	remove, err := v.goMachine.ObserveAt([]uint64{0x401bfbac, 0x401c4598}, func(address uint64) { c.capture(address) })
	if err != nil {
		return nil, err
	}
	return func() error { remove(); return nil }, nil
}

// DecryptALACSample accepts one access unit. It leaves the final partial block
// unchanged, matching the native mode-5 routine. Input is never modified.
// Samples may be up to 128 KiB; malformed or unsupported sizes fail closed.
func (d *ALACGoDecryptor) DecryptALACSample(ctx context.Context, sample []byte) ([]byte, error) {
	if len(sample) == 0 || uint64(len(sample)) > alacLoopCapacity {
		return nil, errors.New("Go ALAC sample size")
	}
	select {
	case d.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-d.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.loop == nil {
		return nil, errors.New("Go ALAC decrypter is closed")
	}
	start := time.Now()
	result, _, err := d.loop.replay(ctx, sample, len(sample))
	d.loop.memory.reset()
	if err != nil {
		return nil, err
	}
	d.stats.Elapsed += time.Since(start)
	d.stats.Samples++
	d.stats.Bytes += uint64(len(sample))
	return result, nil
}

func (d *ALACGoDecryptor) Stats() ALACGoStats {
	d.gate <- struct{}{}
	defer func() { <-d.gate }()
	return d.stats
}

// Clone creates an independent worker from detached setup state. The worker
// owns its pages, may outlive the source, and must be closed by the caller.
// No license request or runtime execution is needed.
func (d *ALACGoDecryptor) Clone(ctx context.Context) (*ALACGoDecryptor, error) {
	select {
	case d.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-d.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.loop == nil {
		return nil, errors.New("Go ALAC decrypter is closed")
	}
	source := d.loop.memory
	if source.read != nil || d.loop.vm != nil {
		return nil, errors.New("Go ALAC setup is not detached")
	}
	m := &alacLoopMemory{
		initial: make(map[uint64][]byte, len(source.initial)), dirty: make(map[uint64][]byte),
		stackLo: source.stackLo, stackHi: source.stackHi,
		sampleLo: source.sampleLo, sampleHi: source.sampleHi,
	}
	for address, page := range source.initial {
		m.initial[address] = bytes.Clone(page)
	}
	return &ALACGoDecryptor{
		gate:  make(chan struct{}, 1),
		loop:  &alacLoopCapture{buffer: d.loop.buffer, state: d.loop.state, memory: m},
		stats: ALACGoStats{SetupPages: len(m.initial)},
	}, nil
}

func (d *ALACGoDecryptor) Close() {
	d.gate <- struct{}{}
	defer func() { <-d.gate }()
	if d.loop != nil {
		d.loop.close()
		d.loop = nil
	}
}
