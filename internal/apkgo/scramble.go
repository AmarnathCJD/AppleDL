package apkgo

import (
	"encoding/binary"

	"github.com/AmarnathCJD/AppleDL/internal/scramble"
)

// scrambleTable adapts the pinned 336-byte table transform to ordinary slices.
func (m *Machine) scrambleTable(end, budget uint64) uint64 {
	const work = 1
	c, base := &m.CPU, m.licenseBase
	if budget < work || m.Hook != nil || m.observer != nil || c.R[9] != 0 ||
		end >= c.PC && end < base+0x19898c {
		return 0
	}
	seed := uint32(c.R[14])
	for lane := range 4 {
		if binary.LittleEndian.Uint32(c.V[1][lane*4:]) != seed ||
			binary.LittleEndian.Uint32(c.V[27][lane*4:]) != 16 {
			return 0
		}
		for group, register := range [...]int{2, 3, 4, 5} {
			if binary.LittleEndian.Uint32(c.V[register][lane*4:]) != uint32(group*4+lane) {
				return 0
			}
		}
	}
	for i := range 16 {
		if c.V[9][i] != byte(i*4) || c.V[26][i] != 0x93 {
			return 0
		}
		for group, register := range [...]int{29, 28, 30, 31} {
			want := byte(255)
			if i%4 == 0 {
				want = byte(group*4 + i/4)
			}
			if c.V[register][i] != want {
				return 0
			}
		}
	}
	data := m.Memory.Slice(c.R[15], 336)
	var tail [16]byte
	copy(tail[:], data[320:])
	defer clear(tail[:])
	scramble.Bytes(data, seed)
	// Preserve the translated caller's final vector state until it is replaced.
	// Only the last block contributes to these scratch values.
	for group, productRegister := range [...]int{16, 7, 18, 20} {
		for lane := range 4 {
			i := group*4 + lane
			position := uint32(320 + i)
			product := position*position - seed*seed
			masked := uint32(tail[i]) ^ seed
			mixed := masked ^ product
			binary.LittleEndian.PutUint32(c.V[group+2][lane*4:], position+16)
			binary.LittleEndian.PutUint32(c.V[productRegister][lane*4:], product)
			if group < 3 {
				register := [...]int{19, 17, 21}[group]
				binary.LittleEndian.PutUint32(c.V[register][lane*4:], masked)
			}
			binary.LittleEndian.PutUint32(c.V[group+22][lane*4:], mixed)
			c.V[6][i] = byte(mixed) * 0x93
		}
	}
	c.R[0], c.R[1], c.R[9] = 0, 0x1000193, 0
	c.R[16] = binary.LittleEndian.Uint64(data[8:])
	c.R[17] = binary.LittleEndian.Uint64(data)
	c.arithmetic(2, ^uint64(2), 1, 64, true)
	c.PC = base + 0x19898c
	return work
}
