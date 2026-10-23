package apkgo

import "math/bits"

func mask(w uint8) uint64 {
	if w >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << w) - 1
}
func signed(v uint64, w uint8) int64 {
	if w >= 64 {
		return int64(v)
	}
	return int64(v<<(64-w)) >> (64 - w)
}
func (c *CPU) readReg(r, w uint8) uint64 {
	if r == 33 {
		return 0
	}
	if r >= 64 {
		return laneGet(c.V[r-64], 0, w)
	}
	return c.R[r] & mask(w)
}
func (c *CPU) writeReg(r, w uint8, v uint64) {
	if r == 33 {
		return
	}
	if r >= 64 {
		c.V[r-64] = [16]byte{}
		lanePut(&c.V[r-64], 0, w, v)
		return
	}
	c.R[r] = v & mask(w)
}
func (c *CPU) value(o operand) uint64 {
	v := o.Value
	if o.Kind == 1 {
		v = c.readReg(o.Reg, o.Width)
		if o.Reg >= 64 && o.Lane != 255 {
			v = laneGet(c.V[o.Reg-64], o.Lane, o.Width)
		}
	}
	switch o.Ext {
	case 1:
		v &= 255
	case 2:
		v &= 65535
	case 3:
		v = uint64(uint32(v))
	case 5:
		v = uint64(int64(int8(v)))
	case 6:
		v = uint64(int64(int16(v)))
	case 7:
		v = uint64(int64(int32(v)))
	}
	switch o.Shift {
	case 1:
		v <<= o.Amount
	case 2:
		v = (v << o.Amount) | mask(o.Amount)
	case 3:
		v >>= o.Amount
	case 4:
		v = uint64(signed(v, o.Width) >> o.Amount)
	case 5:
		if o.Width == 32 {
			v = uint64(bits.RotateLeft32(uint32(v), -int(o.Amount)))
		} else {
			v = bits.RotateLeft64(v, -int(o.Amount))
		}
	}
	return v
}
func (c *CPU) cond(cc uint8) bool {
	n, z, carry, v := c.NZCV>>31&1 != 0, c.NZCV>>30&1 != 0, c.NZCV>>29&1 != 0, c.NZCV>>28&1 != 0
	switch cc {
	case 0, 15, 16:
		return true
	case 1:
		return z
	case 2:
		return !z
	case 3:
		return carry
	case 4:
		return !carry
	case 5:
		return n
	case 6:
		return !n
	case 7:
		return v
	case 8:
		return !v
	case 9:
		return carry && !z
	case 10:
		return !carry || z
	case 11:
		return n == v
	case 12:
		return n != v
	case 13:
		return !z && n == v
	case 14:
		return z || n != v
	}
	panic("condition")
}
func (c *CPU) arithmetic(a, b, carry uint64, w uint8, flags bool) uint64 {
	a &= mask(w)
	b &= mask(w)
	r, cout := bits.Add64(a, b, carry)
	r &= mask(w)
	if w == 32 {
		cout = (a + b + carry) >> 32
	}
	if flags {
		c.NZCV = 0
		if r>>(w-1) != 0 {
			c.NZCV |= 1 << 31
		}
		if r == 0 {
			c.NZCV |= 1 << 30
		}
		if cout != 0 {
			c.NZCV |= 1 << 29
		}
		if ((a^r)&(b^r))>>(w-1)&1 != 0 {
			c.NZCV |= 1 << 28
		}
	}
	return r
}
func (c *CPU) logicFlags(v uint64, w uint8) {
	c.NZCV = 0
	v &= mask(w)
	if v == 0 {
		c.NZCV |= 1 << 30
	}
	if v>>(w-1) != 0 {
		c.NZCV |= 1 << 31
	}
}
func (m *Machine) fail(i instruction) { panic(Fault{m.CPU.PC, opNames[i.Op]}) }
func (m *Machine) step(i instruction, a []operand) {
	c := &m.CPU
	pc := c.PC
	next := pc + 4
	op := i.Op
	if op >= opldr && op <= opstnp {
		m.memoryOp(i, a)
		c.PC = next
		return
	}
	if op >= opldaxr && op <= opstxrb {
		m.atomicOp(i, a)
		c.PC = next
		return
	}
	vector := false
	for _, o := range a {
		vector = vector || o.Kind == 1 && o.Reg >= 64
	}
	if vector {
		m.vectorOp(i, a)
		c.PC = next
		return
	}
	var v uint64
	w := uint8(64)
	if len(a) > 0 && a[0].Kind == 1 {
		w = a[0].Width
	}
	get := func(n int) uint64 { return c.value(a[n]) }
	flags := i.Flags&2 != 0
	switch op {
	case opnop, opdmb, opdsb, opisb, opprfm, opbti, oppaciasp, opautiasp:
	case opmov:
		v = get(1)
	case opmovn:
		v = ^get(1)
	case opmovk:
		v = (get(0) &^ (uint64(65535) << a[1].Amount)) | get(1)
	case opadd, opadds:
		v = c.arithmetic(get(1), get(2), 0, w, flags)
	case opsub, opsubs:
		v = c.arithmetic(get(1), ^get(2), 1, w, flags)
	case opadc, opadcs:
		v = c.arithmetic(get(1), get(2), c.NZCV>>29&1, w, flags)
	case opsbc, opsbcs:
		v = c.arithmetic(get(1), ^get(2), c.NZCV>>29&1, w, flags)
	case opand, opands:
		v = get(1) & get(2)
		if flags {
			c.logicFlags(v, w)
		}
	case opbic, opbics:
		v = get(1) &^ get(2)
		if flags {
			c.logicFlags(v, w)
		}
	case oporr:
		v = get(1) | get(2)
	case opeor:
		v = get(1) ^ get(2)
	case oporn:
		v = get(1) | ^get(2)
	case opeon:
		v = get(1) ^ ^get(2)
	case opmvn:
		v = ^get(1)
	case opneg, opnegs:
		v = c.arithmetic(0, ^get(1), 1, w, flags)
	case opmul:
		v = get(1) * get(2)
	case opmneg:
		v = -(get(1) * get(2))
	case opmadd:
		v = get(1)*get(2) + get(3)
	case opmsub:
		v = get(3) - get(1)*get(2)
	case opumull:
		v = uint64(uint32(get(1))) * uint64(uint32(get(2)))
	case opsmull:
		v = uint64(int64(int32(get(1))) * int64(int32(get(2))))
	case opumaddl:
		v = uint64(uint32(get(1)))*uint64(uint32(get(2))) + get(3)
	case opsmaddl:
		v = uint64(int64(int32(get(1)))*int64(int32(get(2)))) + get(3)
	case opumsubl:
		v = get(3) - uint64(uint32(get(1)))*uint64(uint32(get(2)))
	case opsmsubl:
		v = get(3) - uint64(int64(int32(get(1)))*int64(int32(get(2))))
	case opumulh:
		v, _ = bits.Mul64(get(1), get(2))
	case opsmulh:
		x, y := get(1), get(2)
		v, _ = bits.Mul64(x, y)
		if int64(x) < 0 {
			v -= y
		}
		if int64(y) < 0 {
			v -= x
		}
	case opudiv:
		if b := get(2); b != 0 {
			v = get(1) / b
		}
	case opsdiv:
		if b := signed(get(2), w); b != 0 {
			v = uint64(signed(get(1), w) / b)
		}
	case oplsl:
		v = get(1) << (get(2) % uint64(w))
	case oplsr:
		v = (get(1) & mask(w)) >> (get(2) % uint64(w))
	case opasr:
		v = uint64(signed(get(1), w) >> (get(2) % uint64(w)))
	case opror:
		if w == 32 {
			v = uint64(bits.RotateLeft32(uint32(get(1)), -int(get(2))))
		} else {
			v = bits.RotateLeft64(get(1), -int(get(2)))
		}
	case opextr:
		shift := get(3)
		v = (get(2) >> shift) | (get(1) << (uint64(w) - shift))
	case opubfx:
		v = (get(1) >> get(2)) & mask(uint8(get(3)))
	case opsbfx:
		v = uint64(signed(get(1)>>get(2), uint8(get(3))))
	case opubfiz:
		v = (get(1) & mask(uint8(get(3)))) << get(2)
	case opsbfiz:
		v = uint64(signed(get(1), uint8(get(3)))) << get(2)
	case opbfi:
		shift, width := get(2), uint8(get(3))
		v = (get(0) &^ (mask(width) << shift)) | ((get(1) & mask(width)) << shift)
	case opbfxil:
		width := uint8(get(3))
		v = (get(0) &^ mask(width)) | ((get(1) >> get(2)) & mask(width))
	case opuxtb:
		v = get(1) & 255
	case opuxth:
		v = get(1) & 65535
	case opsxtb:
		v = uint64(int64(int8(get(1))))
	case opsxth:
		v = uint64(int64(int16(get(1))))
	case opsxtw:
		v = uint64(int64(int32(get(1))))
	case opcmp:
		c.arithmetic(get(0), ^get(1), 1, w, true)
	case opcmn:
		c.arithmetic(get(0), get(1), 0, w, true)
	case optst:
		c.logicFlags(get(0)&get(1), w)
	case opcsel, opcsinc, opcsinv, opcsneg:
		if c.cond(i.CC) {
			v = get(1)
		} else {
			v = get(2)
			switch op {
			case opcsinc:
				v++
			case opcsinv:
				v = ^v
			case opcsneg:
				v = -v
			}
		}
	case opcset:
		if c.cond(i.CC) {
			v = 1
		}
	case opcsetm:
		if c.cond(i.CC) {
			v = ^uint64(0)
		}
	case opcinc, opcinv, opcneg:
		v = get(1)
		if c.cond(i.CC) {
			switch op {
			case opcinc:
				v++
			case opcinv:
				v = ^v
			case opcneg:
				v = -v
			}
		}
	case opccmp, opccmn:
		if c.cond(i.CC) {
			if op == opccmp {
				c.arithmetic(get(0), ^get(1), 1, w, true)
			} else {
				c.arithmetic(get(0), get(1), 0, w, true)
			}
		} else {
			c.NZCV = get(2) << 28
		}
	case opadr, opadrp:
		v = get(1) + (m.codeBase - m.current.Address)
	case opb:
		if c.cond(i.CC) {
			next = get(0) + (m.codeBase - m.current.Address)
		}
	case opbl:
		c.R[30] = next
		next = get(0) + (m.codeBase - m.current.Address)
	case opbr:
		next = get(0)
	case opblr:
		next = get(0)
		c.R[30] = pc + 4
	case opret:
		next = c.R[30]
		if len(a) > 0 {
			next = get(0)
		}
	case opcbz, opcbnz:
		if (get(0) == 0) == (op == opcbz) {
			next = get(1) + (m.codeBase - m.current.Address)
		}
	case optbz, optbnz:
		if (get(0)&(1<<get(1)) == 0) == (op == optbz) {
			next = get(2) + (m.codeBase - m.current.Address)
		}
	case opmrs:
		switch a[1].Value {
		case 56962:
			v = c.TLS
		case 55824:
			v = c.NZCV
		default:
			m.fail(i)
		}
	case opmsr:
		switch a[0].Value {
		case 56962:
			c.TLS = get(1)
		case 55824:
			c.NZCV = get(1)
		default:
			m.fail(i)
		}
	case opclz:
		if w == 32 {
			v = uint64(bits.LeadingZeros32(uint32(get(1))))
		} else {
			v = uint64(bits.LeadingZeros64(get(1)))
		}
	case opcls:
		x := get(1)
		if x>>(w-1) != 0 {
			x = ^x
		}
		if w == 32 {
			v = uint64(bits.LeadingZeros32(uint32(x)) - 1)
		} else {
			v = uint64(bits.LeadingZeros64(x) - 1)
		}
	case oprbit:
		if w == 32 {
			v = uint64(bits.Reverse32(uint32(get(1))))
		} else {
			v = bits.Reverse64(get(1))
		}
	case oprev:
		if w == 32 {
			v = uint64(bits.ReverseBytes32(uint32(get(1))))
		} else {
			v = bits.ReverseBytes64(get(1))
		}
	case oprev16:
		x := get(1)
		v = ((x & 0x00ff00ff00ff00ff) << 8) | ((x & 0xff00ff00ff00ff00) >> 8)
	case oprev32:
		x := get(1)
		v = uint64(bits.ReverseBytes32(uint32(x))) | uint64(bits.ReverseBytes32(uint32(x>>32)))<<32
	default:
		m.fail(i)
	}
	// Branches, comparisons and system stores have no destination register.
	switch op {
	case opcmp, opcmn, optst, opccmp, opccmn, opb, opbl, opbr, opblr, opret, opcbz, opcbnz, optbz, optbnz, opnop, opdmb, opdsb, opisb, opprfm, opmsr, opbti, oppaciasp, opautiasp:
	default:
		c.writeReg(a[0].Reg, w, v)
	}
	c.PC = next
}

func (m *Machine) address(o operand) uint64 {
	c := &m.CPU
	v := c.readReg(o.Reg, 64) + o.Value
	if o.Width != 255 {
		index := operand{Kind: 1, Reg: o.Width, Width: o.Lanes, Ext: o.Ext, Shift: o.Shift, Amount: o.Amount}
		v += c.value(index)
	}
	return v
}
func (m *Machine) memoryOp(i instruction, a []operand) {
	op := i.Op
	c := &m.CPU
	n := 1
	pair := op == opldp || op == opldpsw || op == opstp || op == opldnp || op == opstnp
	if pair {
		n = 2
	}
	mo := a[n]
	address := mo.Value + (m.codeBase - m.current.Address)
	if mo.Kind == 3 {
		address = m.address(mo)
	}
	load := op < opstr || op == opldp || op == opldpsw || op == opldnp
	width := a[0].Width
	switch op {
	case opldrb, opldurb, opldrsb, opldursb, opstrb, opsturb:
		width = 8
	case opldrh, opldurh, opldrsh, opldursh, opstrh, opsturh:
		width = 16
	case opldrsw, opldursw, opldpsw:
		width = 32
	}
	sign := op == opldrsb || op == opldursb || op == opldrsh || op == opldursh || op == opldrsw || op == opldursw || op == opldpsw
	for j := 0; j < n; j++ {
		addr := address + uint64(j)*uint64(width/8)
		o := a[j]
		if o.Reg >= 64 {
			if load {
				clear(c.V[o.Reg-64][:])
				copy(c.V[o.Reg-64][:], m.Memory.Slice(addr, uint64(width/8)))
			} else {
				m.Memory.Write(addr, c.V[o.Reg-64][:width/8])
			}
		} else if load {
			v := m.Memory.Get(addr, width)
			if sign {
				v = uint64(signed(v, width))
			}
			c.writeReg(o.Reg, o.Width, v)
		} else {
			m.Memory.Put(addr, c.value(o), width)
		}
	}
	if i.Flags&1 != 0 {
		if len(a) > n+1 {
			address = c.readReg(mo.Reg, 64) + c.value(a[n+1])
		}
		c.writeReg(mo.Reg, 64, address)
	}
}
func (m *Machine) atomicOp(i instruction, a []operand) {
	c := &m.CPU
	op := i.Op
	switch op {
	case opldaxr, opldxr, opldar, opldarb, opldaxrb, opldxrb:
		address := m.address(a[1])
		w := a[0].Width
		if op == opldarb || op == opldaxrb || op == opldxrb {
			w = 8
		}
		c.writeReg(a[0].Reg, a[0].Width, m.Memory.Get(address, w))
		c.Exclusive = address
	case opstlxr, opstxr, opstlxrb, opstxrb:
		address := m.address(a[2])
		w := a[1].Width
		if op == opstlxrb || op == opstxrb {
			w = 8
		}
		if c.Exclusive == address {
			m.Memory.Put(address, c.value(a[1]), w)
			c.writeReg(a[0].Reg, a[0].Width, 0)
		} else {
			c.writeReg(a[0].Reg, a[0].Width, 1)
		}
		c.Exclusive = 0
	case opstlr:
		m.Memory.Put(m.address(a[1]), c.value(a[0]), a[0].Width)
	default:
		m.fail(i)
	}
}
