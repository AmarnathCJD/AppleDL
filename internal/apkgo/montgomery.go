package apkgo

import (
	"encoding/binary"

	"github.com/AmarnathCJD/AppleDL/internal/montgomery"
)

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
