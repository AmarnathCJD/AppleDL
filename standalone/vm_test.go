package standalone

import (
	"context"
	"encoding/binary"
	"testing"
)

func TestGoPthreadOnceABI(t *testing.T) {
	v, err := newGoVM()
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	control := v.alloc(8)
	defer v.free(control)
	callback := v.alloc(32)
	defer v.free(callback)
	// Exercise the actual Go once continuation with a synthetic initializer
	// that increments once and clobbers the caller-saved registers.
	v.goMachine.Hook = func(pc uint64) {
		if pc == callback {
			address := v.reg(regX0) + 4
			v.write(address, binary.LittleEndian.AppendUint32(nil, binary.LittleEndian.Uint32(v.read(address, 4))+1))
			v.setReg(regX0, 0x123)
			v.setReg(regX0+1, 0x456)
			v.setReg(regPC, v.reg(regLR))
		}
	}
	v.setReg(regX0+19, 0x123456)
	for i := 0; i < 2; i++ {
		code, e := v.callAddress(context.Background(), v.stub("pthread_once"), control, callback)
		if e != nil || code != 0 {
			t.Fatalf("pthread_once failed: code=%d err=%v", code, e)
		}
		if binary.LittleEndian.Uint32(v.read(control, 4)) != 2 || binary.LittleEndian.Uint32(v.read(control+4, 4)) != 1 {
			t.Fatal("initializer did not run exactly once")
		}
		if v.reg(regX0+19) != 0x123456 || v.reg(regSP) != arenaBase+0xf0000 {
			t.Fatal("initializer corrupted callee-saved register or stack")
		}
	}
	v.write(control, binary.LittleEndian.AppendUint32(nil, 1))
	if _, err := v.callAddress(context.Background(), v.stub("pthread_once"), control, callback); err == nil {
		t.Fatal("recursive initialization was accepted")
	}
}

func TestGoUnprovisionedWithoutAndroid(t *testing.T) {
	v, err := newGoVM()
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	path := v.string("/adi")
	defer v.free(path)
	loadPath := v.string("/native")
	defer v.free(loadPath)
	androidID := v.string("0123456789abcdef")
	defer v.free(androidID)
	operations := []struct {
		name string
		args []uint64
		want int32
	}{
		{"nf92ngaK92", []uint64{path}, 0},
		{"kq56gsgHG6", []uint64{loadPath}, 0},
		{"nf92ngaK92", []uint64{path}, 0},
		{"Sph98paBcz", []uint64{androidID, 16}, 0},
		{"aslgmuibau", []uint64{^uint64(1)}, -45061},
		{"aslgmuibau", []uint64{^uint64(0)}, -45061},
	}
	for _, op := range operations {
		code, err := v.call(context.Background(), op.name, op.args...)
		if err != nil {
			t.Fatalf("%s: %v", op.name, err)
		}
		if code != op.want {
			t.Fatalf("%s: code %d, expected %d", op.name, code, op.want)
		}
	}
	if len(v.files.data) != 0 {
		t.Fatal("status probe created provisioning files")
	}
	t.Log("Go translated runtime checked V3/V1.5 state without native libraries, Android, Python, network or existing device state")
}
