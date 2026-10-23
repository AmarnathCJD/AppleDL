package standalone

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestGuestThreadSleepTLSAndLockContention(t *testing.T) {
	v, err := newGoVM()
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	lock, args, code, slot := v.alloc(64), v.alloc(48), v.alloc(128), v.alloc(8)
	// Synthetic Go callbacks stand in for translated guest code. Imports and
	// scheduling remain real; no ARM decoder or native engine is required.
	v.goMachine.Hook = func(pc uint64) {
		switch pc {
		case code:
			v.setReg(regSP, v.reg(regSP)-16)
			v.write(v.reg(regSP), binary.LittleEndian.AppendUint64(nil, v.reg(regX0+19)))
			v.setReg(regX0+19, v.reg(regX0))
			v.write(args+8, binary.LittleEndian.AppendUint64(nil, v.reg(regTLS)))
			v.setReg(regX0, 1)
			v.setReg(regLR, code+4)
			v.setReg(regPC, v.stub("sleep"))
		case code + 4:
			if v.reg(regX0+19) != args {
				t.Error("worker lost callee-saved register")
			}
			v.setReg(regX0, lock)
			v.setReg(regLR, code+8)
			v.setReg(regPC, v.stub("pthread_rwlock_rdlock"))
		case code + 8:
			v.write(args, binary.LittleEndian.AppendUint64(nil, binary.LittleEndian.Uint64(v.read(args, 8))+1))
			v.setReg(regX0, lock)
			v.setReg(regLR, code+12)
			v.setReg(regPC, v.stub("pthread_rwlock_unlock"))
		case code + 12:
			v.setReg(regX0+19, binary.LittleEndian.Uint64(v.read(v.reg(regSP), 8)))
			v.setReg(regSP, v.reg(regSP)+16)
			v.setReg(regPC, arenaBase)
		}
	}
	for i, value := range []uint64{0, 0, v.stub("sleep"), lock, v.stub("pthread_rwlock_rdlock"), v.stub("pthread_rwlock_unlock")} {
		v.write(args+uint64(i*8), binary.LittleEndian.AppendUint64(nil, value))
	}
	call := func(name string, a ...uint64) {
		t.Helper()
		status, err := v.callAddress(context.Background(), v.stub(name), a...)
		if err != nil || status != 0 {
			t.Fatalf("%s status=%d err=%v", name, status, err)
		}
	}
	call("pthread_rwlock_wrlock", lock)
	v.setReg(regX0+19, 0x123456)
	call("pthread_create", slot, 0, code, args)
	if len(v.threads) != 2 || v.threads[1].finished || v.threads[1].wake.IsZero() || binary.LittleEndian.Uint64(v.read(slot, 8)) != 2 {
		t.Fatal("worker did not start and sleep")
	}
	if binary.LittleEndian.Uint64(v.read(args, 8)) != 0 {
		t.Fatal("sleep returned early")
	}
	workerTLS := binary.LittleEndian.Uint64(v.read(args+8, 8))
	if workerTLS == 0 || workerTLS == tlsBase || v.reg(regTLS) != tlsBase {
		t.Fatal("thread TLS was shared")
	}
	// Advance the scheduler's test deadline, without waiting a real second.
	v.threads[1].wake = time.Now().Add(-time.Second)
	call("pthread_rwlock_unlock", lock)
	if !v.threads[1].finished || binary.LittleEndian.Uint64(v.read(args, 8)) != 1 {
		t.Fatal("blocked worker did not resume after unlock")
	}
	if v.imports["pthread_rwlock_rdlock"] != 2 {
		t.Fatal("worker did not block and retry the read lock")
	}
	if v.reg(regX0+19) != 0x123456 || v.reg(regSP) != arenaBase+0xf0000 {
		t.Fatal("worker corrupted parent registers or stack")
	}
}

func TestGuestThreadCancellationPoisonsRuntime(t *testing.T) {
	v, err := newGoVM()
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	code, slot := v.alloc(4), v.alloc(8)
	v.instructionLimit = 1_000_000_000
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slices := 0
	v.goMachine.Hook = func(pc uint64) {
		if pc == code {
			slices++
			if slices == 3 {
				cancel()
			}
			v.goMachine.Stop = true // spinning worker exhausts a scheduler slice
		}
	}
	if _, err := v.callAddress(ctx, v.stub("pthread_create"), slot, 0, code, 0); !errors.Is(err, context.Canceled) || v.failure == nil || slices != 3 {
		t.Fatal("spinning worker escaped cancellation")
	}
	if _, err := v.callAddress(context.Background(), code); err == nil {
		t.Fatal("cancelled runtime was reused")
	}
}

func TestGuestThreadSleepLoopYieldsImmediately(t *testing.T) {
	v, err := newGoVM()
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	code, args, slot := v.alloc(64), v.alloc(16), v.alloc(8)
	// Increment and sleep repeatedly. The worker must suspend on its first
	// sleep, even while its parent has already returned.
	v.goMachine.Hook = func(pc uint64) {
		if pc == code {
			v.write(args, binary.LittleEndian.AppendUint64(nil, binary.LittleEndian.Uint64(v.read(args, 8))+1))
			v.setReg(regX0, 1)
			v.setReg(regLR, code)
			v.setReg(regPC, v.stub("sleep"))
		}
	}
	v.write(args+8, binary.LittleEndian.AppendUint64(nil, v.stub("sleep")))
	_, err = v.callAddress(context.Background(), v.stub("pthread_create"), slot, 0, code, args)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(v.read(args, 8)); got != 1 || v.imports["sleep"] != 1 {
		t.Fatalf("worker continued past sleep: increments=%d sleeps=%d", got, v.imports["sleep"])
	}
}
