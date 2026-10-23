package standalone

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"time"
)

const alacLoopPageSize = uint64(4096)
const alacLoopCapacity = uint64(128 * 1024)

type alacLoopState struct {
	r    [32]uint64 // x0..x30, then SP; W writes zero their upper 32 bits.
	zero bool
}

// Setup pages stay private in memory. The fallback is removed before replay;
// writes use separate pages so each sample starts with the same setup state.
type alacLoopMemory struct {
	pages                                [512]*[1024]alacLoopPage
	initial                              map[uint64][]byte
	dirty                                map[uint64][]byte
	read                                 func(uint64, uint64) []byte
	reads                                int
	stackLo, stackHi, sampleLo, sampleHi uint64
}

type alacLoopPage struct {
	data  []byte
	dirty bool
}

func (m *alacLoopMemory) page(address uint64) []byte {
	if address>>22 >= uint64(len(m.pages)) {
		panic("Go ALAC setup address rejected")
	}
	if table := m.pages[address>>22]; table != nil {
		if p := table[address>>12&1023].data; p != nil {
			return p
		}
	}
	return m.loadPage(address)
}

// Sparse page tables avoid hashing on every translated memory access. Maps
// retain ownership for snapshots and cleanup; the table only indexes them.
func (m *alacLoopMemory) loadPage(address uint64) []byte {
	base := address &^ (alacLoopPageSize - 1)
	if m.pages[address>>22] == nil {
		m.pages[address>>22] = new([1024]alacLoopPage)
	}
	entry := &m.pages[address>>22][address>>12&1023]
	if p := m.dirty[base]; p != nil {
		*entry = alacLoopPage{data: p, dirty: true}
		return p
	}
	if p := m.initial[base]; p != nil {
		entry.data = p
		return p
	}
	if m.read == nil {
		panic("Go ALAC setup page missing")
	}
	if len(m.initial) >= 4096 {
		panic("Go ALAC setup page limit")
	}
	// Reads are limited to the runtime's mapped library/arena address spaces.
	if !(base >= 0x10000000 && base < 0x50000000 || base >= arenaBase && base < heapLimit) {
		panic("Go ALAC setup address rejected")
	}
	p := m.read(base, alacLoopPageSize)
	m.reads++
	m.initial[base] = p
	entry.data = p
	return p
}

func (m *alacLoopMemory) get8(address uint64) uint64 {
	return uint64(m.page(address)[address&(alacLoopPageSize-1)])
}

func (m *alacLoopMemory) get32(address uint64) uint64 {
	offset := address & (alacLoopPageSize - 1)
	if offset <= alacLoopPageSize-4 {
		return uint64(binary.LittleEndian.Uint32(m.page(address)[offset:]))
	}
	var value uint64
	for i := uint64(0); i < 4; i++ {
		value |= m.get8(address+i) << (8 * i)
	}
	return value
}

func (m *alacLoopMemory) get64(address uint64) uint64 {
	offset := address & (alacLoopPageSize - 1)
	if offset <= alacLoopPageSize-8 {
		return binary.LittleEndian.Uint64(m.page(address)[offset:])
	}
	return m.get32(address) | m.get32(address+4)<<32
}

func (m *alacLoopMemory) writable(address, size uint64) []byte {
	if address+size < address || !(address >= m.stackLo && address+size <= m.stackHi || address >= m.sampleLo && address+size <= m.sampleHi) {
		panic("Go ALAC write outside private stack/sample")
	}
	base := address &^ (alacLoopPageSize - 1)
	page := m.page(address)
	entry := &m.pages[address>>22][address>>12&1023]
	if entry.dirty {
		return page
	}
	p := bytes.Clone(page)
	m.dirty[base] = p
	*entry = alacLoopPage{data: p, dirty: true}
	return p
}

func (m *alacLoopMemory) put8(address, value uint64) {
	m.writable(address, 1)[address&(alacLoopPageSize-1)] = byte(value)
}

func (m *alacLoopMemory) put32(address, value uint64) {
	offset := address & (alacLoopPageSize - 1)
	if offset <= alacLoopPageSize-4 {
		binary.LittleEndian.PutUint32(m.writable(address, 4)[offset:], uint32(value))
		return
	}
	for i := uint64(0); i < 4; i++ {
		m.put8(address+i, value>>(8*i))
	}
}

func (m *alacLoopMemory) put64(address, value uint64) {
	offset := address & (alacLoopPageSize - 1)
	if offset <= alacLoopPageSize-8 {
		binary.LittleEndian.PutUint64(m.writable(address, 8)[offset:], value)
		return
	}
	m.put32(address, value)
	m.put32(address+4, value>>32)
}

// Copy whole page spans rather than resolving the page for every byte.
func (m *alacLoopMemory) copyIn(address uint64, data []byte) {
	for len(data) > 0 {
		offset := address & (alacLoopPageSize - 1)
		n := min(len(data), int(alacLoopPageSize-offset))
		copy(m.writable(address, uint64(n))[offset:], data[:n])
		address += uint64(n)
		data = data[n:]
	}
}

func (m *alacLoopMemory) copyOut(data []byte, address uint64) {
	for len(data) > 0 {
		offset := address & (alacLoopPageSize - 1)
		n := min(len(data), int(alacLoopPageSize-offset))
		copy(data[:n], m.page(address)[offset:offset+uint64(n)])
		address += uint64(n)
		data = data[n:]
	}
}

func (m *alacLoopMemory) reset() {
	for base, p := range m.dirty {
		clear(p)
		if table := m.pages[base>>22]; table != nil {
			table[base>>12&1023] = alacLoopPage{data: m.initial[base]}
		}
	}
	clear(m.dirty)
}

func (m *alacLoopMemory) close() {
	m.reset()
	for _, p := range m.initial {
		clear(p)
	}
	clear(m.initial)
	clear(m.pages[:])
	m.read = nil
}

type alacLoopCapture struct {
	vm                             *goVM
	ctx                            context.Context
	buffer                         uint64
	size                           int
	state                          alacLoopState
	memory                         *alacLoopMemory
	first                          []byte
	endState                       alacLoopState
	entered, ended, registerParity bool
	err                            error
	duration                       time.Duration
}

func alacReadRegisters(v *goVM) (s alacLoopState) {
	for i := 0; i < 29; i++ {
		s.r[i] = v.reg(regX0 + i)
	}
	s.r[29], s.r[30], s.r[31] = v.reg(1), v.reg(regLR), v.reg(regSP)
	s.zero = v.reg(3)&(1<<30) != 0 // UC_ARM64_REG_NZCV
	return
}

func (c *alacLoopCapture) capture(address uint64) uintptr {
	defer func() {
		if recover() != nil {
			c.err = errors.New("Go ALAC capture failed")
			c.vm.stopExecution()
		}
	}()
	if uint64(address) == 0x401c4598 {
		if c.entered && !c.ended {
			c.ended = true
			s := alacReadRegisters(c.vm)
			c.registerParity = s == c.endState
		}
		return 0
	}
	if c.entered {
		return 0
	}
	c.entered = true
	c.state = alacReadRegisters(c.vm)
	sp := c.state.r[31]
	if sp < arenaBase+0x10000 || sp >= arenaBase+0xf0000 || arenaBase+0xf0000-sp > 256*1024 {
		c.err = errors.New("Go ALAC capture stack bound")
		return 0
	}
	c.memory = &alacLoopMemory{
		initial: map[uint64][]byte{}, dirty: map[uint64][]byte{}, read: c.vm.read,
		stackLo: sp, stackHi: arenaBase + 0xf0000,
		sampleLo: c.buffer, sampleHi: c.buffer + alacLoopCapacity,
	}
	// Reserve the entire reusable sample buffer, including pages not touched
	// by this first sample, so later samples never fetch native memory.
	for a := c.buffer &^ (alacLoopPageSize - 1); a < c.buffer+alacLoopCapacity; a += alacLoopPageSize {
		c.memory.page(a)
	}
	start := time.Now()
	c.first, c.endState, c.err = c.replay(c.ctx, nil, c.size)
	c.duration = time.Since(start)
	return 0
}

// replay never executes ARM instructions. A nil input preserves the captured
// sample. A supplied input replaces it while restoring the initial registers.
func (c *alacLoopCapture) replay(ctx context.Context, input []byte, size int) (result []byte, state alacLoopState, err error) {
	defer func() {
		if recover() != nil {
			clear(result)
			result = nil
			err = errors.New("Go ALAC replay failed")
		}
	}()
	m := c.memory
	m.reset()
	state = c.state
	if size < 1 || uint64(size) > alacLoopCapacity || input != nil && len(input) != size {
		return nil, state, errors.New("Go ALAC replay sample bound")
	}
	m.sampleHi = c.buffer + uint64(size)
	if input != nil {
		m.copyIn(c.buffer, input)
	}
	for i := 0; i < size/16; i++ {
		if i%64 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, state, err
			}
		}
		alacLoopBlock(&state, m)
	}
	result = make([]byte, size)
	m.copyOut(result, c.buffer)
	return result, state, nil
}

func (c *alacLoopCapture) close() {
	clear(c.first)
	c.state, c.endState = alacLoopState{}, alacLoopState{}
	if c.memory != nil {
		c.memory.close()
	}
}
