package standalone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func syntheticALACLoopMemory() *alacLoopMemory {
	return &alacLoopMemory{
		initial: map[uint64][]byte{heapBase: make([]byte, 4096), heapBase + 4096: make([]byte, 4096)},
		dirty:   map[uint64][]byte{}, sampleLo: heapBase, sampleHi: heapBase + 8192,
	}
}

func TestALACBulkCopyAndCloneIsolation(t *testing.T) {
	m := syntheticALACLoopMemory()
	input := bytes.Repeat([]byte{0xa5}, 4200)
	m.copyIn(heapBase+100, input)
	got := make([]byte, len(input))
	m.copyOut(got, heapBase+100)
	if !bytes.Equal(got, input) || m.initial[heapBase][100] != 0 {
		t.Fatal("bulk copy crossed a page incorrectly or mutated setup")
	}
	m.reset()
	d := &ALACGoDecryptor{gate: make(chan struct{}, 1), loop: &alacLoopCapture{buffer: heapBase + 4090, memory: m}}
	var workers []*ALACGoDecryptor
	for range 8 {
		w, err := d.Clone(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		workers = append(workers, w)
	}
	d.Close() // Clones must survive clearing the original pages.
	var wg sync.WaitGroup
	for _, w := range workers {
		wg.Go(func() {
			defer w.Close()
			for i := range 20 {
				input := bytes.Repeat([]byte{byte(i)}, 15)
				got, err := w.DecryptALACSample(context.Background(), input)
				if err != nil || !bytes.Equal(got, input) {
					t.Error("worker state leaked across samples or clones")
				}
			}
		})
	}
	wg.Wait()
	if _, err := d.Clone(context.Background()); err == nil {
		t.Fatal("cloned closed source")
	}
}

func TestALACLoopPrivateMemory(t *testing.T) {
	m := syntheticALACLoopMemory()
	defer m.close()
	// Cross-page, little-endian reads/writes must agree and never mutate the
	// immutable setup. Reset must isolate the next sample from this sample.
	m.put64(heapBase+4093, 0x0102030405060708)
	if m.get64(heapBase+4093) != 0x0102030405060708 || m.get32(heapBase+4095) != 0x03040506 {
		t.Fatal("cross-page memory semantics differ")
	}
	if m.initial[heapBase][4093] != 0 || m.initial[heapBase+4096][0] != 0 {
		t.Fatal("setup was mutated")
	}
	old := m.dirty[heapBase]
	m.reset()
	if m.get64(heapBase+4093) != 0 || !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatal("sample reset failed")
	}
	for _, write := range []func(){
		func() { m.put8(heapBase-1, 1) },
		func() { m.put32(heapBase+8191, 1) },
		func() { m.put64(^uint64(0)-3, 1) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("out-of-range write accepted")
				}
			}()
			write()
		}()
	}
}

func TestALACGoDetachedLifecycle(t *testing.T) {
	m := syntheticALACLoopMemory()
	d := &ALACGoDecryptor{gate: make(chan struct{}, 1), loop: &alacLoopCapture{buffer: heapBase + 16, memory: m}}
	defer d.Close()
	for size := 1; size < 16; size++ {
		sample := bytes.Repeat([]byte{byte(size)}, size)
		result, err := d.DecryptALACSample(context.Background(), sample)
		if err != nil || !bytes.Equal(result, sample) {
			t.Fatal("partial-block tail changed")
		}
		result[0] ^= 1
		if sample[0] != byte(size) {
			t.Fatal("input aliased output")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.DecryptALACSample(ctx, []byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	for _, sample := range [][]byte{nil, make([]byte, alacLoopCapacity+1)} {
		if _, err := d.DecryptALACSample(context.Background(), sample); err == nil {
			t.Fatal("size bound ignored")
		}
	}
	if d.Stats().Samples != 15 {
		t.Fatal("failed calls counted as successes")
	}
	if fmt.Sprintf("%#v", d) != "ALACGoDecryptor{redacted}" {
		t.Fatal("private state formatting exposed")
	}
	page := m.initial[heapBase]
	page[0] = 123
	d.Close()
	d.Close()
	if page[0] != 0 {
		t.Fatal("private setup not cleared on close")
	}
	if _, err := d.DecryptALACSample(context.Background(), []byte{1}); err == nil {
		t.Fatal("closed decrypter accepted work")
	}
}

func TestALACGoMissingFrozenPageFailsClosed(t *testing.T) {
	m := syntheticALACLoopMemory()
	d := &ALACGoDecryptor{gate: make(chan struct{}, 1), loop: &alacLoopCapture{buffer: heapBase + 8192, memory: m}}
	defer d.Close()
	result, err := d.DecryptALACSample(context.Background(), []byte{1})
	if err == nil || result != nil || d.Stats().Samples != 0 {
		t.Fatal("missing setup returned output")
	}
}
