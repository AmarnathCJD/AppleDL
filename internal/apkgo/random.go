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

// twistTableRandom recognizes the second caller's obfuscated MT19937 update.
// The generator operates on an ordinary State; only boundary state lives here.
func (m *Machine) twistTableRandom(end, budget uint64) uint64 {
	const work = 1
	c, r, base := &m.CPU, &m.CPU.R, m.licenseBase
	if budget < work || m.Hook != nil || m.observer != nil ||
		end >= c.PC && end < base+0x194158 ||
		r[12] != 0 || r[9] != 4 || r[20] != 7 ||
		r[0] != 0x9ece02f8 || r[1] != 0xcf67017d || r[2] != 0x1312f74e ||
		r[3] != base+0x193e94 || r[4] != base+0x193f4c ||
		r[22]+r[23]+0xb5b != 224 {
		return 0
	}
	address, table, vectors := r[17], base+0xdb0, r[32]+0x19d0
	if rangesOverlap(address, 624*4, table, 44) ||
		rangesOverlap(address, 624*4, r[28], 8) ||
		rangesOverlap(address, 624*4, vectors, 48) ||
		m.Memory.Get(r[28], 32) != 0x74a177f0 ||
		m.Memory.Get(r[28]+4, 32) != 0xeda9c72f {
		return 0
	}
	for _, branch := range [...][2]uint64{{0, 0}, {1, 0x70}, {3, 0x78}, {4, 0}, {5, 0xb8}, {9, 0}, {10, 0xac}} {
		if m.Memory.Get(table+branch[0]*4, 32) != branch[1] {
			return 0
		}
	}
	data := m.Memory.Slice(address, 624*4)
	first := binary.LittleEndian.Uint32(data)
	for lane := range 4 {
		for _, constant := range [...][2]uint32{
			{1, first}, {5, 0x80000000}, {6, 0x7ffffffe},
			{7, 0x9ece02f8}, {16, 0xcf67017d}, {17, 0x1312f74e},
		} {
			if binary.LittleEndian.Uint32(c.V[constant[0]][lane*4:]) != constant[1] {
				return 0
			}
		}
		for i, value := range [...]uint32{0x28124777, 0xb966610f, 0x72ccc21c} {
			if m.Memory.Get(vectors+uint64(i*16+lane*4), 32) != uint64(value) {
				return 0
			}
		}
	}
	var state mt19937.State
	defer clear(state[:])
	for i := range state {
		state[i] = binary.LittleEndian.Uint32(data[i*4:])
	}
	last := [4]uint32(state[620:624])
	defer clear(last[:])
	state.Twist()
	writeRandomState(data, &state)
	// The translated continuation still sees the last SIMD group's scratch
	// values. They are computed directly, without executing either loop.
	for lane, next := range last {
		matrix := uint32(0x74a177f0)
		if next&1 != 0 {
			matrix ^= 0x9908b0df
		}
		distant := state[392+lane]
		for _, value := range [...][2]uint32{
			{0, next}, {1, next}, {2, distant ^ matrix ^ 0x28124777},
			{3, distant}, {4, next * 2}, {7, 0x72ccc21c},
			{16, 0xb966610f}, {17, 0x28124777},
		} {
			binary.LittleEndian.PutUint32(c.V[value[0]][lane*4:], value[1])
		}
	}
	r[0], r[8], r[9] = 0x13ff, 14, 7
	r[10], r[11], r[12] = uint64(state[623]), table, 0x49ac0d62
	r[13], r[14], r[15], r[16] = 1, 0x7a1af524, uint64(last[3]), 0x3aa4aa95
	c.arithmetic(0, ^uint64(0), 1, 64, true)
	c.PC = base + 0x194158
	return work
}
