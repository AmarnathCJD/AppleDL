package apkgo

import (
	"encoding/binary"

	"github.com/AmarnathCJD/AppleDL/internal/montgomery"
)

func (m *Machine) inverseMontgomery(end, budget uint64) uint64 {
	const operations = 432
	c, r, base := &m.CPU, &m.CPU.R, m.licenseBase
	if budget < operations || r[14] != 1 || r[9] != 1 || r[10] != 1 || r[11] != 0 ||
		r[13] != r[8] || r[21] != 0xaae || r[12] != base+0x56f2e4 || r[27] != base+0xdb0 ||
		end > c.PC && end < base+0x56f38c {
		return 0
	}
	table := r[27]
	if m.Memory.Get(table+0xaae*4, 32) != 0 || m.Memory.Get(table+0xaaf*4, 32) != 0x34 ||
		m.Memory.Get(table+0xab5*4, 32) != 0x50 {
		return 0
	}
	word := uint32(r[8])
	if word&1 == 0 {
		return 0
	}
	destination := r[19] + 0x10
	if rangesOverlap(destination, 4, table+0xab5*4, 4) {
		return 0
	}
	// The original loop's scratch accumulator is overwritten at 0x56f388
	// before any read. Include that overwrite in the adapter boundary so no
	// instruction-specific arithmetic is needed to reconstruct the scratch value.
	stackWord := m.Memory.Get(r[32]+0x12e4, 32)
	m.Memory.Put(destination, uint64(montgomery.NegativeInverse(word)), 32)
	r[8], r[9] = 0xc1f03ba, 0x24c
	r[10] = uint64(int64(int32(m.Memory.Get(table+0xacd*4, 32))))
	r[11], r[12], r[13], r[14] = base+0x56f368, 0x8e73d0ea, 0x882, stackWord
	r[15], r[16], r[17] = base+0x12a7f4, base+0x56f318, base+0x12a87c
	r[26] = 0xea8fbbaa5061c9d9
	c.arithmetic(31, ^uint64(31), 1, 32, true)
	c.PC = base + 0x56f38c
	return operations
}

func (m *Machine) multiplyMontgomery(end, budget uint64) uint64 {
	c, r := &m.CPU, &m.CPU.R
	n := r[28]
	if n < 2 || n > 256 || r[9] != n || r[12] != 0xf69 || r[8] != n*4 ||
		r[19] != 0xfffff08c || r[27] != r[24]-4 ||
		m.Memory.Get(r[32]+0x1ab0, 32) != n ||
		end > c.PC && end < m.licenseBase+0x573f18 {
		return 0
	}
	operations := 28*n*n + 51*n + 35
	if budget < operations {
		return 0
	}
	destination := m.Memory.Get(r[25]+0x210, 64) + r[24]
	left := m.Memory.Get(r[26]+r[20], 64) + r[24]
	rightHandle := m.Memory.Get(r[32]+0x1aa0, 64)
	right := m.Memory.Get(rightHandle+r[20], 64) + r[24]
	modulus := m.Memory.Get(r[22]+r[20], 64) + r[24]
	parameters := m.Memory.Get(r[32]+0x1ae0, 64)
	scratch := r[32] + 0x1a80
	for _, area := range [][2]uint64{
		{left, n * 4}, {right, n * 4}, {modulus, n * 4}, {r[25] + 0x210, 8},
		{r[26] + r[20], 8}, {rightHandle + r[20], 8}, {r[22] + r[20], 8},
		{parameters + 0x10, 4}, {r[32] + 0x1ae0, 8}, {r[32] + 0x1aa0, 8},
		{r[32] + 0x1ab0, 4}, {r[32] + 0x12e8, 8},
	} {
		if rangesOverlap(destination, (n+1)*4, area[0], area[1]) ||
			rangesOverlap(scratch, 8, area[0], area[1]) {
			return 0
		}
	}
	if rangesOverlap(destination, (n+1)*4, scratch, 8) {
		return 0
	}
	out := m.Memory.Slice(destination, (n+1)*4)
	for _, value := range out {
		if value != 0 {
			return 0
		}
	}
	inA, inB, mod := m.Memory.Slice(left, n*4), m.Memory.Slice(right, n*4), m.Memory.Slice(modulus, n*4)
	inverse := uint32(m.Memory.Get(parameters+0x10, 32))
	if inverse*binary.LittleEndian.Uint32(mod) != ^uint32(0) {
		return 0
	}
	var a, b, modulusWords [256]uint32
	var result [257]uint32
	for i := range n {
		a[i] = binary.LittleEndian.Uint32(inA[i*4:])
		b[i] = binary.LittleEndian.Uint32(inB[i*4:])
		modulusWords[i] = binary.LittleEndian.Uint32(mod[i*4:])
	}
	lastColumn := montgomery.Multiply(result[:n+1], a[:n], b[:n], modulusWords[:n], inverse)
	for i, word := range result[:n+1] {
		binary.LittleEndian.PutUint32(out[i*4:], word)
	}
	m.Memory.Put(scratch, uint64(a[0]), 64)
	// Preserve the old caller's boundary state until that caller is replaced.
	r[0], r[1], r[2] = m.licenseBase+0x573d54, 0xf6b, m.licenseBase+0x573ea0
	r[3], r[4], r[5] = n, 0xf73, m.licenseBase+0x573c80
	r[6], r[7] = uint64(lastColumn), m.Memory.Get(r[32]+0x12e8, 64)
	r[9], r[10], r[11] = 0xf70, m.licenseBase+0x573f18, 0x59f
	r[12], r[13], r[14], r[15] = m.licenseBase+0x573cf0, 0xaef, n, n
	r[16], r[17], r[21] = 0xaed, 0xf77, r[32]+0x1bc98
	c.arithmetic(n, ^n, 1, 32, true)
	c.PC = r[10]
	clear(a[:])
	clear(b[:])
	clear(modulusWords[:])
	clear(result[:])
	return operations
}

func (m *Machine) squareMontgomery(end, budget uint64) uint64 {
	c, r := &m.CPU, &m.CPU.R
	n := r[26]
	if n < 2 || n > 256 || r[9] != n || r[10] != 0xb7a || r[8] != n*4 ||
		r[19] != 0xffffdfa9 || r[27] != r[24]-4 ||
		end > c.PC && end < m.licenseBase+0x5730b0 {
		return 0
	}
	operations := 27*n*n + 53*n + 41
	if budget < operations {
		return 0
	}
	destination := m.Memory.Get(r[25]+0x210, 64) + r[24]
	input := m.Memory.Get(r[28]+r[20], 64) + r[24]
	modulus := m.Memory.Get(r[22]+r[20], 64) + r[24]
	parameters := m.Memory.Get(r[32]+0x1ae0, 64)
	for _, area := range [][2]uint64{
		{input, n * 4}, {modulus, n * 4}, {r[25] + 0x210, 8},
		{r[28] + r[20], 8}, {r[22] + r[20], 8}, {parameters + 0x10, 4},
		{r[32] + 0x1ae0, 8}, {r[32] + 0x1a70, 8}, {r[32] + 0x12e8, 8},
	} {
		if rangesOverlap(destination, (n+1)*4, area[0], area[1]) {
			return 0
		}
	}
	out := m.Memory.Slice(destination, (n+1)*4)
	for _, value := range out {
		if value != 0 {
			return 0
		}
	}
	in, mod := m.Memory.Slice(input, n*4), m.Memory.Slice(modulus, n*4)
	inverse := uint32(m.Memory.Get(parameters+0x10, 32))
	if inverse*binary.LittleEndian.Uint32(mod) != ^uint32(0) {
		return 0
	}
	var operand, modulusWords [256]uint32
	var result [257]uint32
	for i := range n {
		operand[i] = binary.LittleEndian.Uint32(in[i*4:])
		modulusWords[i] = binary.LittleEndian.Uint32(mod[i*4:])
	}
	montgomery.Square(result[:n+1], operand[:n], modulusWords[:n], inverse)
	for i, word := range result[:n+1] {
		binary.LittleEndian.PutUint32(out[i*4:], word)
	}
	// Preserve the old caller's boundary state until that caller is replaced.
	r[0], r[1], r[2] = 1, m.licenseBase+0x57303c, 0xb68
	r[3], r[7] = m.Memory.Get(r[32]+0x1a70, 64), m.Memory.Get(r[32]+0x12e8, 64)
	r[4], r[5], r[6] = destination-r[24]+(n-1)*4, m.licenseBase+0x572e84, uint64(operand[n-1])
	r[9], r[10], r[11] = m.licenseBase+0x5730b0, 0xb60, m.licenseBase+0x572ee0
	r[12], r[13], r[14], r[15] = n, n, 0xb66, m.licenseBase+0x572ee0
	r[16], r[17], r[28] = 0xb73, 0xb7b, m.licenseBase+0x56f6fc
	c.arithmetic(n, ^n, 1, 64, true)
	c.PC = r[9]
	clear(operand[:])
	clear(modulusWords[:])
	clear(result[:])
	return operations
}

func (m *Machine) encodeMontgomery(end, budget uint64) uint64 {
	c, r, base := &m.CPU, &m.CPU.R, m.licenseBase
	words := uint64(uint32(r[8]))
	// The exit precedes the entry in the image; internal stops still lie above it.
	if words > 256 || r[20] != 7 || end > c.PC && end < base+0x575674 {
		return 0
	}
	size := uint64(uint32(m.Memory.Get(r[32]+0x1a00, 64)))
	if size == 0 || size > 1024 {
		return 0
	}
	groups := (size + 3) / 4
	loaded := min(words, groups)
	operations := 34 + 26*size + 20*loaded + 9*(groups-loaded)
	if budget < operations {
		return 0
	}
	table := base + 0xdb0
	for _, entry := range [...]struct {
		index  uint64
		offset int32
	}{
		{0xc58, 0xc8}, {0xc5a, -0x68}, {0xc5b, 0x24}, {0xc5c, -0x8c},
		{0xc5d, 0x40}, {0xc5e, -0x130}, {0xc5f, -0x40}, {0xc60, 0x28},
	} {
		if int32(m.Memory.Get(table+entry.index*4, 32)) != entry.offset {
			return 0
		}
	}
	destination := r[19]
	if rangesOverlap(destination, size, table+0xc58*4, 9*4) {
		return 0
	}
	var values [256]uint32
	if loaded != 0 {
		input := m.Memory.Get(r[27]+0x338, 64) + r[24]
		if rangesOverlap(destination, size, input, loaded*4) ||
			rangesOverlap(destination, size, r[27]+0x338, 8) {
			return 0
		}
		in := m.Memory.Slice(input, loaded*4)
		for i := range loaded {
			values[i] = binary.LittleEndian.Uint32(in[i*4:])
		}
	}
	montgomery.PutBytes(m.Memory.Slice(destination, size), values[:loaded], 0x7a)
	var last uint32
	if groups <= loaded {
		last = values[groups-1]
	}
	shift := (size - 1) % 4 * 8
	// Retain the translated caller's boundary state until that caller is replaced.
	r[0], r[1], r[2], r[3], r[4] = 0x8758cf5f, base+0x575624, base+0x575648, 0x409, 0xf4
	r[5], r[6], r[7] = base+0x5755bc, base+0x57548c, uint64(last>>shift^0x7a)
	r[9], r[10], r[11], r[12] = loaded, 0, 0xdf31acf4, 0x20ce5f5e
	r[13], r[14], r[15], r[16], r[17] = shift+8, 0xc7d, base+0x5755fc, uint64(last), 0x78a730a3
	r[21], r[22], r[23], r[25] = uint64(last>>shift), 0, table, 0xc59
	c.arithmetic(0, ^uint64(0), 1, 64, true)
	c.PC = base + 0x57548c
	clear(values[:])
	return operations
}

func (m *Machine) decodeMontgomery(end, budget uint64) uint64 {
	c, r, base := &m.CPU, &m.CPU.R, m.licenseBase
	size := r[9]
	if size == 0 || size > 1024 || r[8] != 0 {
		return 0
	}
	adjusted := c.PC == base+0x56ec24
	exit := base + 0x56ed9c
	source := r[28]
	var bias byte
	if adjusted {
		exit, source, bias = base+0x56ef8c, r[19], 0x32
	}
	if end > c.PC && end < exit {
		return 0
	}
	full, remainder := size/4, size%4
	operations := 116 * full
	if remainder != 0 {
		operations += 53 + 24*remainder
	}
	if adjusted {
		operations = 121 * full
		if remainder != 0 {
			operations += 39 + 26*remainder
		}
	}
	if budget < operations {
		return 0
	}
	table := base + 0xdb0
	if adjusted {
		if r[0] != 0xa80 || r[1] != base+0x56ec84 || r[2] != 7 || r[7] != table ||
			r[11] != base+0x56ec24 || r[12] != 0x556 || r[13] != 0x12 || r[14] != ^uint64(0xaa5) ||
			r[15] != base+0x56ec4c || r[16] != 0x20eb4287 || r[17] != base+0x56ecb4 {
			return 0
		}
	} else if r[0] != 0x63175eed || r[1] != base+0x56eb28 || r[2] != 0xffffea7f ||
		r[3] != 0xa6c || r[4] != 13 || r[5] != 0xab7 || r[6] != base+0x56eafc ||
		r[10] != 0xd80030fd || r[11] != 0x27ffceff || r[12] != base+0x56ea90 || r[13] != 0x8dfe9fee ||
		r[15] != base+0x56eac8 || r[16] != 0xabf || r[17] != 0x9ce8a119 || r[20] != 0xaba || r[25] != table {
		return 0
	}
	// The adapters are only valid for the pinned caller and branch table. Keep
	// unexpected control state on the reference path while that caller remains.
	entries := [...]int32{
		0x38, 0x68, 0x28, -0x38, 0x294, 0xac, 0x3c, 0x38, 0x74, 0x3c, 0x48, 0xf4,
		0, 0x34, -0x90, 0x2d8, 0x4c, -0x3c, 0x24, 0x50, 0x170, 0x34, 0x60, 0xb8,
		0x38, 0x68, 0x9c, 0x44, 0x7e0, -0x34, 0x204, -0x98, 0x274, 0x34, 0x2b8, 0x38, 0x48, -0x38,
	}
	for i, offset := range entries {
		if int32(m.Memory.Get(table+uint64(0xaa2+i)*4, 32)) != offset {
			return 0
		}
	}
	words := (size + 3) / 4
	destination := m.Memory.Get(r[23]+0x120, 64) + r[24]
	for _, area := range [...][2]uint64{
		{source, size}, {r[23] + 0x120, 8}, {table + 0xaa2*4, uint64(len(entries)) * 4},
	} {
		if rangesOverlap(destination, words*4, area[0], area[1]) {
			return 0
		}
	}
	var values [256]uint32
	montgomery.SetBytes(values[:words], m.Memory.Slice(source, size), bias)
	out := m.Memory.Slice(destination, words*4)
	for i, word := range values[:words] {
		binary.LittleEndian.PutUint32(out[i*4:], word)
	}
	// These boundary registers disappear when the surrounding caller is ported.
	if adjusted {
		r[3], r[8], r[20] = words, words, 0xaad
		if remainder == 0 {
			r[4], r[5], r[6] = destination-r[24]+(words-1)*4, 0, uint64(values[words-1]&0xff000000)
			r[9], r[10] = 0, exit
			c.arithmetic(0, ^uint64(0), 1, 64, true)
		} else {
			r[2], r[4], r[5], r[6] = remainder*8, 0xaa2, 0xaa5, base+0x56ef18
			r[8], r[9], r[10] = full+0xaad, exit, base+0x56ef50
			r[11], r[12], r[13] = destination-r[24]+full*4, 0xa0d, 0xa0
			c.arithmetic(0, ^(remainder * 8), 1, 32, true)
		}
	} else {
		r[7], r[19] = words, 0xac8
		if remainder == 0 {
			r[8], r[9], r[14], r[21], r[22] = words, 0, exit, 0xac1, base+0x56eb28
			c.arithmetic(0, ^uint64(0), 1, 64, true)
		} else {
			r[8], r[9], r[10], r[11] = full+0xac8, exit, base+0x56ed68, base+0x56ed00
			r[12], r[13], r[14], r[20], r[21], r[22] = 11, 0xa1804edc, uint64(values[words-1]), 0xabf, base+0x56ed00, table
			c.arithmetic(remainder*8, ^uint64(0), 1, 32, true)
		}
	}
	c.PC = exit
	clear(values[:])
	return operations
}
