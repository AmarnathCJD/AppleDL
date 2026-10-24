package apkgo

// These loops replace the pinned image's most frequently repeated arithmetic.
// Their operation counts retain the interpreter's scheduling/cancellation bound.
// An instruction hook uses the reference path, including stops inside a loop.
func (m *Machine) licenseLoop(end, budget uint64) uint64 {
	offset := m.CPU.PC - m.licenseBase
	switch offset {
	case 0x572c98:
		if used := m.squareMontgomery(end, budget); used != 0 {
			return used
		}
	case 0x1e2ba8:
		if used := m.seedRandom(end, budget); used != 0 {
			return used
		}
	case 0x1e296c:
		if used := m.temperRandom(end, budget); used != 0 {
			return used
		}
	case 0x572dd4:
		if budget >= 27 && (end < m.CPU.PC || end > m.licenseBase+0x572e3c) {
			return m.multiplyAccumulate(budget)
		}
	case 0x1e3484:
		if budget >= 21 && (end < m.CPU.PC || end > m.licenseBase+0x1e34d4) {
			return m.twistTail(budget)
		}
	case 0x1e3358:
		if used := m.twistRandom(end, budget); used != 0 {
			return used
		}
		if budget >= 33 && (end < m.CPU.PC || end > m.licenseBase+0x1e33d8) {
			return m.twistHead(budget)
		}
	}
	if offset < 0x800000 {
		return m.licenseBlock(end, budget)
	}
	return 0
}

// multiplyAccumulate advances two linked base-2^32 multiplication carries.
// Reading each limb before writing it preserves the original in-place ordering.
func (m *Machine) multiplyAccumulate(budget uint64) uint64 {
	c, mem := &m.CPU, &m.Memory
	r := &c.R
	entry := c.PC
	var used uint64
	for budget-used >= 27 {
		offset := r[16] * 4
		dst := mem.Get(r[25]+0x210, 64) + offset
		left := mem.Get(r[28]+r[20], 64) + offset
		right := mem.Get(r[22]+r[20], 64)
		r[16]++
		addend := mem.Get(dst+r[24], 32)
		limb := mem.Get(left+r[24], 32)
		shiftBase := uint64(uint32(r[0] + 3))
		other := mem.Get(right+offset+r[24], 32)
		sum := addend + (r[13] >> 32) + limb*uint64(uint32(r[17]))
		carry := (r[15] >> ((shiftBase - 0xb58) & 63)) + uint64(uint32(sum)) + other*uint64(uint32(r[14]))
		branch := uint32(r[0])
		if r[16] == r[9] {
			branch++
		}
		mem.Put(dst+r[27], carry, 32)
		table := m.licenseBase + 0xdb0
		target := uint64(int64(int32(mem.Get(table+uint64(int64(int32(branch)))*4, 32)))) + r[7]
		r[1], r[2], r[3], r[4], r[5], r[6] = shiftBase, target, table, dst, right, limb
		r[13], r[15] = sum, carry
		c.arithmetic(r[16], ^r[9], 1, 64, true)
		c.PC = target
		used += 27
		if target != entry {
			break
		}
	}
	return used
}

// twistTail updates MT19937 words 227..622. The earlier words have already
// been updated, so these reads deliberately observe the newly written state.
func (m *Machine) twistTail(budget uint64) uint64 {
	c, mem := &m.CPU, &m.Memory
	r := &c.R
	entry := c.PC
	var used uint64
	for budget-used >= 21 {
		address := r[1] + r[11]*4
		previous := uint32(r[8]) & 0x80000000
		increment := r[10] ^ r[2]
		r[11] += increment
		next := uint32(mem.Get(address+0x390, 32))
		distant := uint32(mem.Get(address, 32))
		odd := uint32(mem.Get(r[23]+uint64(next&1)*4, 32))
		joined := previous | next&0x7ffffffe
		value := odd ^ distant ^ joined>>1
		branch := uint32(r[9])
		if r[11] == 396 {
			branch++
		}
		mem.Put(address+0x38c, uint64(value), 32)
		index := uint32(uint64(branch) + r[21])
		table := m.licenseBase + 0xdb0
		target := uint64(int64(int32(mem.Get(table+uint64(int64(int32(index)))*4, 32)))) + r[3]
		r[8], r[12], r[13], r[14], r[15], r[16], r[17] = uint64(next), target, table, uint64(branch), uint64(distant), increment, uint64(next&0x7ffffffe)
		c.arithmetic(r[11], ^uint64(396), 1, 64, true)
		c.PC = target
		used += 21
		if target != entry {
			break
		}
	}
	return used
}

// twistHead updates the first 226 MT19937 words in pairs. The image uses a
// two-word matrix table; keep it as input rather than assuming its contents.
func (m *Machine) twistHead(budget uint64) uint64 {
	c, mem := &m.CPU, &m.Memory
	r := &c.R
	entry := c.PC
	var used uint64
	for budget-used >= 33 {
		salt := uint64(uint32(r[11] + 7))
		address := r[1] + r[9]*4
		previous := uint32(r[13]) & 0x80000000
		index := (salt ^ r[3]) | r[9]
		r[9] += 2
		far1 := uint32(mem.Get(address+0x634, 32))
		next := uint32(mem.Get(r[1]+index*4, 32))
		after := uint32(mem.Get(r[1]+r[9]*4, 32))
		far2 := uint32(mem.Get(address+0x638, 32))
		odd1 := uint32(mem.Get(r[23]+uint64(next&1)*4, 32))
		odd2 := uint32(mem.Get(r[23]+uint64(after&1)*4, 32))
		joined := next&0x80000000 | after&0x7ffffffe
		value1 := far1 ^ (previous|next&0x7ffffffe)>>1 ^ odd1
		value2 := far2 ^ joined>>1 ^ odd2
		mem.Put(address, uint64(value1), 32)
		mem.Put(address+4, uint64(value2), 32)
		branch := uint32(r[11])
		if r[9] == 226 {
			branch++
		}
		table := m.licenseBase + 0xdb0
		target := uint64(int64(int32(mem.Get(table+uint64(int64(int32(branch)))*4, 32)))) + r[4]
		r[0], r[8], r[10], r[12], r[13], r[14], r[15], r[16], r[17] = uint64(after&1), salt, uint64(after), 226, uint64(after), target, uint64(odd2), uint64(far2^joined>>1), uint64(joined)
		c.arithmetic(r[9], ^uint64(226), 1, 64, true)
		c.PC = target
		used += 33
		if target != entry {
			break
		}
	}
	return used
}
