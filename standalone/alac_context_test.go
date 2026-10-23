package standalone

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/AmarnathCJD/AppleDL/internal/envelope"
)

func TestALACPortableContextLifecycleAndBinding(t *testing.T) {
	m := &alacLoopMemory{initial: map[uint64][]byte{}, dirty: map[uint64][]byte{}, stackLo: arenaBase + 0xee000, stackHi: arenaBase + 0xf0000, sampleLo: heapBase, sampleHi: heapBase + alacLoopCapacity}
	for a := heapBase; a < heapBase+alacLoopCapacity; a += alacLoopPageSize {
		m.initial[a] = bytes.Repeat([]byte{0x55}, int(alacLoopPageSize))
	}
	// Real captures can omit the untouched first stack page.
	d := &ALACGoDecryptor{gate: make(chan struct{}, 1), loop: &alacLoopCapture{buffer: heapBase, memory: m}}
	d.loop.state.r[31] = m.stackLo
	defer d.Close()
	binding := sha256.Sum256([]byte("fixture-ciphertext-and-ordinal"))
	blob, err := d.ExportContext(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(blob)
	plain, err := envelope.Decode("AMCTX001", blob, stateLimit)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot alacContextSnapshot
	if json.Unmarshal(plain, &snapshot) != nil {
		t.Fatal("invalid export")
	}
	clear(plain)
	defer snapshot.destroy()
	for _, p := range snapshot.Pages {
		if p.Address >= heapBase && p.Address < heapBase+alacLoopCapacity && !bytes.Equal(p.Data, make([]byte, alacLoopPageSize)) {
			t.Fatal("export retained sample data")
		}
	}
	clone, err := ImportALACGoDecryptor(context.Background(), blob, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clone.Close()
	d.Close()
	got, err := clone.DecryptALACSample(context.Background(), []byte{1, 2, 3})
	if err != nil || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatal("import did not survive source close", err)
	}
	wrong := binding
	wrong[0] ^= 1
	if c, err := ImportALACGoDecryptor(context.Background(), blob, wrong); err == nil {
		c.Close()
		t.Fatal("wrong binding accepted")
	}
	bad := bytes.Clone(blob)
	bad[len(bad)/2] ^= 1
	if c, err := ImportALACGoDecryptor(context.Background(), bad, binding); err == nil {
		c.Close()
		t.Fatal("corrupt context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ImportALACGoDecryptor(ctx, blob, binding); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled import accepted")
	}
	if _, err := d.ExportContext(context.Background(), binding); err == nil {
		t.Fatal("closed export accepted")
	}
}
