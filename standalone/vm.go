// Package standalone runs build-time translated APK operations in Go. Default
// builds use portable Go storage and contain no native library loader.
package standalone

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/AmarnathCJD/AppleDL/internal/apkgo"
)

const (
	stubBase    = uint64(0x60000000)
	arenaBase   = uint64(0x70000000)
	tlsBase     = arenaBase + 0x1000
	heapBase    = arenaBase + 0x100000
	heapLimit   = arenaBase + 0x3f00000
	bufferLimit = 4 << 20
	regX0       = 199
	regLR       = 2
	regSP       = 4
	regPC       = 260
	regTLS      = 262
	regCPACR    = 261
	onceCode    = arenaBase + 0x100
)

type goVM struct {
	goMachine        *apkgo.Machine
	goContexts       map[uint64]apkgo.CPU
	exports          map[string]uint64
	libraries        map[string]uint64
	stubs            map[uint64]string
	symbolStubs      map[string]uint64
	imports          map[string]int
	systemProperties map[string]string
	constructors     []uint64
	heap             uint64
	allocated        map[uint64]uint64
	freed            map[uint64]uint64
	failure          error
	files            *virtualFiles
	instructionLimit uint64
	threads          []*guestThread
	currentThread    *guestThread
	rwlocks          map[uint64]*guestRWLock
	onceOwners       map[uint64]uint64
	yieldThread      bool
}

func (v *goVM) handleImport(address uint64) uintptr {
	defer func() {
		if recover() != nil {
			v.failure = errors.New("native import failed")
			v.stopExecution()
		}
	}()
	name, ok := v.stubs[uint64(address)]
	if !ok {
		panic("unknown import")
	}
	v.imports[name]++
	var args [8]uint64
	for i := range args {
		args[i] = v.reg(regX0 + i)
	}
	if name == "pthread_once" {
		state := binary.LittleEndian.Uint32(v.read(args[0], 4))
		switch state {
		case 0:
			v.onceOwners[args[0]] = v.currentThread.id
			v.write(args[0], binary.LittleEndian.AppendUint32(nil, 1))
			// Run the initializer in the current emulation, preserving its native
			// stack. The initializer continues within the current execution slice.
			v.setReg(regPC, onceCode)
			return 0
		case 2:
			v.setReg(regX0, 0)
			v.setReg(regPC, v.reg(regLR))
			return 0
		default:
			if v.onceOwners[args[0]] != v.currentThread.id {
				v.currentThread.onceWait = args[0]
				v.suspendThread()
				return 0
			}
			v.failure = errors.New("recursive or invalid native once initialization")
			v.stopExecution()
			return 0
		}
	}
	result, err := v.importCall(name, args)
	if err != nil {
		v.failure = fmt.Errorf("native import %s unavailable", name)
		v.stopExecution()
		return 0
	}
	if v.currentThread.lockWait == 0 {
		v.setReg(regX0, result)
		v.setReg(regPC, v.reg(regLR))
	}
	if v.yieldThread {
		v.yieldThread = false
		v.suspendThread()
	}
	return 0
}

func (v *goVM) saveCPU(id uint64)              { v.goContexts[id] = v.goMachine.CPU }
func (v *goVM) restoreCPU(id uint64)           { v.goMachine.CPU = v.goContexts[id] }
func (v *goVM) mapMemory(address, size uint64) { v.goMachine.Memory.Map(address, size) }
func (v *goVM) read(address, size uint64) []byte {
	if size > bufferLimit {
		panic("guest buffer bound")
	}
	return v.goMachine.Memory.Read(address, size)
}
func (v *goVM) write(address uint64, data []byte) {
	if len(data) > bufferLimit {
		panic("guest buffer bound")
	}
	v.goMachine.Memory.Write(address, data)
}
func (v *goVM) reg(reg int) uint64           { return v.goRegister(reg) }
func (v *goVM) setReg(reg int, value uint64) { v.setGoRegister(reg, value) }

func (v *goVM) alloc(size uint64) uint64 {
	if size > bufferLimit {
		panic("native allocation bound")
	}
	size = (max(size, 1) + 15) &^ 15
	for ptr, capacity := range v.freed {
		if capacity >= size {
			delete(v.freed, ptr)
			v.allocated[ptr] = capacity
			v.write(ptr, make([]byte, capacity))
			return ptr
		}
	}
	if v.heap+size > heapLimit {
		panic("native heap exhausted")
	}
	ptr := v.heap
	v.heap += size
	v.allocated[ptr] = size
	return ptr
}

func (v *goVM) free(ptr uint64) {
	if ptr == 0 {
		return
	}
	size, ok := v.allocated[ptr]
	if !ok {
		panic("invalid native free")
	}
	v.write(ptr, make([]byte, size))
	delete(v.allocated, ptr)
	v.freed[ptr] = size
}

func (v *goVM) cstr(ptr uint64, limit uint64) []byte {
	if limit > bufferLimit {
		panic("native string bound")
	}
	var out []byte
	for i := uint64(0); i < limit; i++ {
		value := v.read(ptr+i, 1)[0]
		if value == 0 {
			return out
		}
		out = append(out, value)
	}
	return out
}

func (v *goVM) data(data []byte) uint64 {
	ptr := v.alloc(uint64(len(data)))
	v.write(ptr, data)
	return ptr
}

func (v *goVM) string(value string) uint64 { return v.data(append([]byte(value), 0)) }

func (v *goVM) stub(name string) uint64 {
	if ptr, ok := v.symbolStubs[name]; ok {
		return ptr
	}
	ptr := stubBase + uint64(len(v.stubs))*4
	if ptr >= stubBase+0x10000 {
		panic("import bound")
	}
	v.symbolStubs[name], v.stubs[ptr] = ptr, name
	return ptr
}

func (v *goVM) call(ctx context.Context, name string, args ...uint64) (int32, error) {
	address, ok := v.exports[name]
	if !ok {
		return 0, errors.New("native export unavailable")
	}
	code, err := v.callAddress(ctx, address, args...)
	if err != nil {
		return code, fmt.Errorf("native %s: %w", name, err)
	}
	return code, nil
}

func (v *goVM) callAddress(ctx context.Context, address uint64, args ...uint64) (code int32, err error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if v.failure != nil {
		return 0, v.failure
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			v.failure = errors.New("native execution failed")
			err = v.failure
		}
	}()
	if v.currentThread != v.threads[0] {
		v.currentThread = v.threads[0]
		v.restoreCPU(v.currentThread.cpu)
	}
	for i := range 8 {
		var value uint64
		if i < len(args) {
			value = args[i]
		}
		v.setReg(regX0+i, value)
	}
	v.setReg(regSP, arenaBase+0xf0000)
	v.setReg(regLR, arenaBase)
	v.setReg(regPC, address)
	if err := v.runThreads(ctx); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		v.failure = errors.New("native call completed after cancellation; close and reopen device before further work")
		return 0, v.failure
	}
	return int32(v.reg(regX0)), nil
}

func (v *goVM) close() {
	if v.goMachine != nil {
		v.goMachine.Memory.Close()
		v.goMachine.CPU = apkgo.CPU{}
		clear(v.goContexts)
		v.goMachine = nil
	}
}
