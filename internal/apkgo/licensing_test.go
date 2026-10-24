package apkgo

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"testing"
)

func licenseFixture(t *testing.T, offset uint64, seed uint64) *Machine {
	t.Helper()
	image, err := Load("libCoreLSKD.so")
	if err != nil {
		t.Fatal(err)
	}
	m := &Machine{}
	const base = uint64(0x40000000)
	m.Add(image, base)
	var end uint64
	for _, s := range image.Segments {
		end = max(end, s.Address+s.Size)
	}
	m.Memory.Map(base, end)
	for _, s := range image.Segments {
		m.Memory.Write(base+s.Address, s.Data)
	}
	const data = uint64(0x80000000)
	m.Memory.Map(data, 0x10000)
	rng := rand.New(rand.NewPCG(seed, seed+1))
	for i := range m.CPU.R {
		m.CPU.R[i] = rng.Uint64()
	}
	for i := range m.CPU.V {
		for j := range m.CPU.V[i] {
			m.CPU.V[i][j] = byte(rng.Uint32())
		}
	}
	m.CPU.NZCV = rng.Uint64()
	for i := uint64(0); i < 0x10000; i += 8 {
		m.Memory.Put(data+i, rng.Uint64(), 64)
	}
	r := &m.CPU.R
	m.CPU.PC = base + offset
	var branch uint64
	var exitOffset uint64
	switch offset {
	case 0x572dd4:
		r[0] = 0xb75
		r[7] = m.CPU.PC
		r[9] = 9
		r[16] = 1
		r[20] = 16
		r[22], r[25], r[28] = data+0x100, data+0x200, data+0x500
		r[24] = 0
		r[27] = uint64(seed%3) * 4
		m.Memory.Put(r[25]+0x210, data+0x1000, 64)
		m.Memory.Put(r[28]+r[20], data+0x2000, 64)
		m.Memory.Put(r[22]+r[20], data+0x3000, 64)
		if seed%2 == 0 {
			m.Memory.Put(r[22]+r[20], data+0x1000, 64)
		}
		branch = r[0]
		exitOffset = 0x6c
	case 0x1e3484:
		r[1] = data + 0x1000
		r[2], r[10] = 6, 7
		r[3] = m.CPU.PC
		r[9], r[21] = 17, 0
		r[11] = uint64(seed % 397)
		if r[11] == 396 {
			r[11] = 395
		}
		r[23] = data + 0x3000
		branch = r[9]
		exitOffset = 0x54
	case 0x1e3358:
		r[1] = data + 0x1000
		r[9] = 2 * (seed % 113)
		r[11] = 10
		r[3] = (r[11] + 7) ^ 1
		r[4] = m.CPU.PC
		r[23] = data + 0x3000
		branch = r[11]
		exitOffset = 0x84
	}
	m.Memory.Put(base+0xdb0+branch*4, 0, 32)
	m.Memory.Put(base+0xdb0+(branch+1)*4, exitOffset, 32)
	return m
}

func TestSelectiveObserverParity(t *testing.T) {
	for _, offset := range []uint64{0x572dd4, 0x1e3484, 0x1e3358} {
		original := licenseFixture(t, offset, 1)
		entry := original.CPU.PC
		end := entry + map[uint64]uint64{0x572dd4: 0x6c, 0x1e3484: 0x54, 0x1e3358: 0x84}[offset]
		for _, delta := range []uint64{0, 4, 16, 20} {
			for _, budget := range []uint64{1, 20, 28, 34, 80, 10000} {
				fast, slow := cloneLicenseMachine(original), cloneLicenseMachine(original)
				slow.licenseBase = 0
				var visits [2][]CPU
				for i, machine := range []*Machine{fast, slow} {
					points := []uint64{entry + delta, entry + delta, end}
					remove, err := machine.ObserveAt(points, func(uint64) {
						visits[i] = append(visits[i], machine.CPU)
					})
					if err != nil {
						t.Fatal(err)
					}
					points[0] = 0 // registration must own its input
					if err := machine.Run(end, budget); err != nil {
						t.Fatal(err)
					}
					remove()
					remove()
				}
				if fast.CPU != slow.CPU || fast.Steps != slow.Steps || !slices.Equal(visits[0], visits[1]) {
					t.Fatalf("observer mismatch offset=%x delta=%d budget=%d visits=%d/%d", offset, delta, budget, len(visits[0]), len(visits[1]))
				}
				for i := range fast.Memory.regions {
					if !bytes.Equal(fast.Memory.regions[i].data, slow.Memory.regions[i].data) {
						t.Fatal("observer changed execution memory")
					}
				}
				fast.Memory.Close()
				slow.Memory.Close()
			}
		}
		original.Memory.Close()
	}
}

func TestSelectiveObserverControl(t *testing.T) {
	m := licenseFixture(t, 0x572dd4, 1)
	defer m.Memory.Close()
	entry := m.CPU.PC
	for _, stop := range []bool{false, true} {
		m.CPU.PC, m.Steps = entry, 0
		remove, err := m.ObserveAt([]uint64{entry}, func(uint64) {
			if stop {
				m.Stop = true
			} else {
				m.CPU.PC = entry + 0x6c
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Run(entry+0x6c, 10000); err != nil || m.Steps != 0 {
			t.Fatalf("observer control executed an instruction: %v", err)
		}
		if _, err := m.ObserveAt([]uint64{entry}, func(uint64) {}); err == nil {
			t.Fatal("second observer accepted")
		}
		remove()
		newRemove, err := m.ObserveAt([]uint64{entry}, func(uint64) {})
		if err != nil {
			t.Fatal(err)
		}
		remove() // stale cleanup must not remove a newer observer
		if m.observer == nil {
			t.Fatal("stale removal cleared new observer")
		}
		newRemove()
	}
	if _, err := m.ObserveAt(nil, func(uint64) {}); err == nil {
		t.Fatal("empty points accepted")
	}
	if _, err := m.ObserveAt([]uint64{entry}, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
	if _, err := m.ObserveAt([]uint64{entry + 1}, func(uint64) {}); err == nil {
		t.Fatal("unaligned point accepted")
	}
	m.Hook = func(uint64) {}
	if _, err := m.ObserveAt([]uint64{entry}, func(uint64) {}); err == nil {
		t.Fatal("observer accepted with global hook")
	}
}

func cloneLicenseMachine(m *Machine) *Machine {
	c := *m
	c.Memory.regions = nil
	for _, r := range m.Memory.regions {
		c.Memory.regions = append(c.Memory.regions, region{r.start, bytes.Clone(r.data)})
	}
	return &c
}

func TestLicenseLoopsMatchInterpreter(t *testing.T) {
	for _, offset := range []uint64{0x572dd4, 0x1e3484, 0x1e3358} {
		for seed := uint64(0); seed < 12; seed++ {
			original := licenseFixture(t, offset, seed)
			for _, budget := range []uint64{1, 20, 21, 22, 26, 27, 28, 32, 33, 34, 80, 1000, 10000} {
				fast, slow := cloneLicenseMachine(original), cloneLicenseMachine(original)
				slow.licenseBase = 0
				end := original.CPU.PC + map[uint64]uint64{0x572dd4: 0x6c, 0x1e3484: 0x54, 0x1e3358: 0x84}[offset]
				if err := fast.Run(end, budget); err != nil {
					t.Fatalf("fast offset=%x seed=%d budget=%d: %v", offset, seed, budget, err)
				}
				if err := slow.Run(end, budget); err != nil {
					t.Fatalf("slow offset=%x seed=%d budget=%d: %v", offset, seed, budget, err)
				}
				if fast.CPU != slow.CPU {
					for i := range fast.CPU.R {
						if fast.CPU.R[i] != slow.CPU.R[i] {
							t.Errorf("offset=%x seed=%d budget=%d register=%d", offset, seed, budget, i)
						}
					}
					t.Fatalf("CPU mismatch offset=%x seed=%d budget=%d pcMatch=%t flagsMatch=%t", offset, seed, budget, fast.CPU.PC == slow.CPU.PC, fast.CPU.NZCV == slow.CPU.NZCV)
				}
				if fast.Steps != slow.Steps {
					t.Fatal("instruction accounting mismatch")
				}
				for i := range fast.Memory.regions {
					if !bytes.Equal(fast.Memory.regions[i].data, slow.Memory.regions[i].data) {
						t.Fatalf("memory mismatch offset=%x seed=%d budget=%d", offset, seed, budget)
					}
				}
				fast.Memory.Close()
				slow.Memory.Close()
			}
			original.Memory.Close()
		}
	}
}

func TestLicenseLoopIntermediateStops(t *testing.T) {
	for _, offset := range []uint64{0x572dd4, 0x1e3484, 0x1e3358} {
		original := licenseFixture(t, offset, 1)
		for delta := uint64(4); delta <= 20; delta += 4 {
			fast, slow := cloneLicenseMachine(original), cloneLicenseMachine(original)
			slow.licenseBase = 0
			end := original.CPU.PC + delta
			if err := fast.Run(end, 1000); err != nil {
				t.Fatal(err)
			}
			if err := slow.Run(end, 1000); err != nil {
				t.Fatal(err)
			}
			if fast.CPU != slow.CPU || fast.Steps != slow.Steps {
				t.Fatal("intermediate stop skipped")
			}
			fast.Memory.Close()
			slow.Memory.Close()
		}
		original.Memory.Close()
	}
}
