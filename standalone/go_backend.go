package standalone

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/AmarnathCJD/AppleDL/internal/apkgo"
)

// newGoVM owns Go memory and CPU state. No DLL, ELF loader, JIT, subprocess,
// Python runtime, or Android device is used on this path.
func newGoVM() (v *goVM, err error) {
	v = &goVM{goMachine: &apkgo.Machine{}, goContexts: map[uint64]apkgo.CPU{}, exports: map[string]uint64{}, libraries: map[string]uint64{}, stubs: map[uint64]string{}, symbolStubs: map[string]uint64{}, imports: map[string]int{}, heap: heapBase, allocated: map[uint64]uint64{}, freed: map[uint64]uint64{}, files: newVirtualFiles(), instructionLimit: 20_000_000}
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("initialize Go runtime failed")
		}
		if err != nil {
			v.close()
			v = nil
		}
	}()
	v.goMachine.Import = func(address uint64) { v.handleImport(address) }
	v.mapMemory(stubBase, 0x10000)
	v.mapMemory(arenaBase, 0x4000000)
	v.setReg(regCPACR, 3<<20)
	v.setReg(regTLS, tlsBase)
	v.initThreads()
	for n, name := range []string{"libCoreADI.so", "libstoreapi.so"} {
		if err = v.loadGoImage(name, uint64(n+1)*0x10000000); err != nil {
			return v, err
		}
	}
	for _, address := range v.constructors {
		if _, err = v.callAddress(context.Background(), address); err != nil {
			return v, err
		}
	}
	return v, nil
}
func (v *goVM) stopExecution() {
	v.goMachine.Stop = true
}
func (v *goVM) goRegister(reg int) uint64 {
	c := &v.goMachine.CPU
	if reg >= regX0 && reg <= regX0+28 {
		return c.R[reg-regX0]
	}
	switch reg {
	case 1:
		return c.R[29]
	case regLR:
		return c.R[30]
	case regSP:
		return c.R[32]
	case regPC:
		return c.PC
	case regTLS:
		return c.TLS
	case regCPACR:
		return c.CPACR
	case 3:
		return c.NZCV
	}
	panic("Go register unsupported")
}
func (v *goVM) setGoRegister(reg int, value uint64) {
	c := &v.goMachine.CPU
	if reg >= regX0 && reg <= regX0+28 {
		c.R[reg-regX0] = value
		return
	}
	switch reg {
	case 1:
		c.R[29] = value
	case regLR:
		c.R[30] = value
	case regSP:
		c.R[32] = value
	case regPC:
		c.PC = value
	case regTLS:
		c.TLS = value
	case regCPACR:
		c.CPACR = value
	case 3:
		c.NZCV = value
	default:
		panic("Go register unsupported")
	}
}
func (v *goVM) loadGoImage(name string, base uint64) error {
	i, err := apkgo.Load(name)
	if err != nil {
		return err
	}
	var end uint64
	for _, s := range i.Segments {
		end = max(end, s.Address+s.Size)
	}
	v.mapMemory(base, (end+4095)&^4095)
	for _, s := range i.Segments {
		v.goMachine.Memory.Write(base+s.Address, s.Data)
	}
	for name, offset := range i.Exports {
		if _, ok := v.exports[name]; !ok {
			v.exports[name] = base + offset
		}
	}
	for _, r := range i.Relocs {
		target := base + r.Addend
		if r.Symbol != "" {
			var ok bool
			target, ok = v.exports[r.Symbol]
			if !ok {
				target = v.stub(r.Symbol)
			}
			target += r.Addend
		}
		v.write(base+r.Address, binary.LittleEndian.AppendUint64(nil, target))
	}
	for offset := uint64(0); offset < i.Init[1]; offset += 8 {
		address := binary.LittleEndian.Uint64(v.read(base+i.Init[0]+offset, 8))
		if address != 0 && address != ^uint64(0) {
			v.constructors = append(v.constructors, address)
		}
	}
	v.libraries[name] = base
	v.goMachine.Add(i, base)
	return nil
}
