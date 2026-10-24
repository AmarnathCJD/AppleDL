package apkgo

import (
	"encoding/binary"

	"github.com/AmarnathCJD/AppleDL/internal/mt19937"
)

// These adapters preserve the pinned image's calling state while its callers
// are replaced. The algorithms themselves have no dependency on the machine.
func (m *Machine) seedRandom(end, budget uint64) uint64 {
	const operations = 623 * 13
	c, r := &m.CPU, &m.CPU.R
	if budget < operations || end > c.PC && end < m.licenseBase+0x1e2bdc ||
		r[8] != 1 || r[13] != 1812433253 || r[14] != 0x2a7e ||
		r[15] != 0x54daf || r[16] != c.PC {
		return 0
	}
	data := m.Memory.Slice(r[12], 624*4)
	if uint64(binary.LittleEndian.Uint32(data)) != r[0] {
		return 0
	}
	var state mt19937.State
	state.Seed(uint32(r[0]))
	writeRandomState(data, &state)
	r[0], r[8], r[9] = uint64(state[623]), 624, 0x54fc0
	r[10], r[11] = m.licenseBase+0x1e2bdc, m.licenseBase+0xdb0
	c.arithmetic(623, ^uint64(623), 1, 32, true)
	c.PC = r[10]
	clear(state[:])
	return operations
}

func (m *Machine) twistRandom(end, budget uint64) uint64 {
	const operations = 113*33 + 24 + 18 + 396*21 + 37
	c, r := &m.CPU, &m.CPU.R
	if budget < operations || end > c.PC && end < m.licenseBase+0x1e3598 ||
		r[9] != 0 || r[11] != 0x2a6e || r[2] != 0x7fffffef ||
		r[3] != 0x2a74 || r[4] != c.PC || r[5] != m.licenseBase+0x1e33dc ||
		r[6] != 0xffffd58e || r[21] != 0x2a73 {
		return 0
	}
	if m.Memory.Get(r[23], 64) != 0x9908b0df00000000 {
		return 0
	}
	indexAddress := r[32] + 0x1d1b4
	index := m.Memory.Get(indexAddress, 32)
	used := uint64(operations)
	if index > 623 {
		used += 11
	}
	if budget < used {
		return 0
	}
	data := m.Memory.Slice(r[1], 624*4)
	if uint64(binary.LittleEndian.Uint32(data)) != r[13] ||
		rangesOverlap(r[1], 624*4, r[23], 8) || rangesOverlap(r[1], 624*4, indexAddress, 4) {
		return 0
	}
	var state mt19937.State
	for i := range state {
		state[i] = binary.LittleEndian.Uint32(data[i*4:])
	}
	last := state[623]
	state.Twist()
	writeRandomState(data, &state)
	if index > 623 {
		m.Memory.Put(indexAddress, 0, 32)
	}
	// Only the boundary values needed by the existing caller remain here.
	r[0], r[2], r[3] = 0x3aa4aa95, 0x2a76, m.licenseBase+0x1e3484
	r[8], r[9], r[10], r[11] = 7, 7, m.licenseBase+0x1e3598, m.licenseBase+0x1e34d8
	r[12] = uint64(state[396])
	if state[0]&1 != 0 {
		r[12] ^= 0x9908b0df
	}
	r[13], r[14] = uint64(last&0x80000000), r[32]+0x1cdf0
	r[15], r[16], r[17] = uint64(state[395]), 1, uint64(last&0x7ffffffe)
	c.arithmetic(index, ^uint64(623), 1, 32, true)
	c.PC = r[10]
	clear(state[:])
	return used
}

func (m *Machine) temperRandom(end, budget uint64) uint64 {
	const operations = 34
	c, r := &m.CPU, &m.CPU.R
	if budget < operations || end > c.PC && end < m.licenseBase+0x1e29f4 ||
		r[8] != 0 || r[9] != 1 || r[10] != 1 || r[21] != 0x2a73 {
		return 0
	}
	value := uint32(r[20])
	shifted := value ^ value>>11
	r[16] = 0xfffffffff26b5ca1
	m.Memory.Put(r[28]+r[16], r[11], 32)
	r[0], r[8], r[9] = 0x3aa4aa95, uint64(mt19937.Temper(value)), 0
	r[10], r[11] = 0x74b9ebee&0x8b463e7d, m.licenseBase+0x1e29f4
	r[12], r[13] = uint64(shifted^shifted<<7&0x9d2c5680), 0x74b9ebee
	c.PC = r[11]
	return operations
}

func writeRandomState(data []byte, state *mt19937.State) {
	for i, word := range state {
		binary.LittleEndian.PutUint32(data[i*4:], word)
	}
}

func rangesOverlap(a, sizeA, b, sizeB uint64) bool {
	if a <= b {
		return b-a < sizeA
	}
	return a-b < sizeB
}
