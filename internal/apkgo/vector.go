package apkgo

import (
	"encoding/binary"
	"math"
	"math/bits"
)

func laneGet(v [16]byte, l, w uint8) uint64 {
	p := int(l) * int(w) / 8
	switch w {
	case 8:
		return uint64(v[p])
	case 16:
		return uint64(binary.LittleEndian.Uint16(v[p:]))
	case 32:
		return uint64(binary.LittleEndian.Uint32(v[p:]))
	case 64:
		return binary.LittleEndian.Uint64(v[p:])
	}
	panic("invalid lane width")
}
func lanePut(v *[16]byte, l, w uint8, x uint64) {
	p := int(l) * int(w) / 8
	switch w {
	case 8:
		v[p] = byte(x)
	case 16:
		binary.LittleEndian.PutUint16(v[p:], uint16(x))
	case 32:
		binary.LittleEndian.PutUint32(v[p:], uint32(x))
	case 64:
		binary.LittleEndian.PutUint64(v[p:], x)
	default:
		panic("invalid lane width")
	}
}
func (c *CPU) lane(o operand, l uint8) uint64 {
	if o.Kind != 1 || o.Reg < 64 {
		return c.value(o)
	}
	if o.Lane != 255 {
		l = o.Lane
	}
	return laneGet(c.V[o.Reg-64], l, o.Width)
}
func laneCount(o operand) uint8 {
	if o.Lanes != 0 {
		return o.Lanes
	}
	return 1
}
func vectorBytes(o operand) int { return int(o.Width) * int(laneCount(o)) / 8 }
func (m *Machine) vectorOp(i instruction, a []operand) {
	c := &m.CPU
	op := i.Op
	if op >= opld1 && op <= opst4 || op == opld1r {
		m.structureOp(i, a)
		return
	}
	d := a[0]
	var out [16]byte
	if op == opmov || op == opins || op == opumov || op == opsmov || op == opfmov {
		s := a[1]
		if d.Reg >= 64 && s.Kind == 1 && s.Reg >= 64 && d.Lane == 255 && s.Lane == 255 && vectorBytes(d) > 8 {
			copy(out[:vectorBytes(d)], c.V[s.Reg-64][:vectorBytes(d)])
			c.V[d.Reg-64] = out
			return
		}
		v := c.lane(s, 0)
		if op == opsmov {
			v = uint64(signed(v, s.Width))
		}
		if op == opfmov && s.Kind == 2 && d.Width == 32 {
			v = uint64(math.Float32bits(float32(math.Float64frombits(v))))
		}
		if d.Reg < 64 {
			c.writeReg(d.Reg, d.Width, v)
			return
		}
		if d.Lane != 255 {
			lanePut(&c.V[d.Reg-64], d.Lane, d.Width, v)
		} else {
			lanePut(&out, 0, d.Width, v)
			c.V[d.Reg-64] = out
		}
		return
	}
	if op == opfcmp {
		m.floatCompare(i, a)
		return
	}
	if d.Reg < 64 {
		m.floatConvert(i, a)
		return
	}
	w, n := d.Width, laneCount(d)
	if op == opbsl || op == opbit || op == opbif {
		old, x, y := c.V[d.Reg-64], c.V[a[1].Reg-64], c.V[a[2].Reg-64]
		for j := 0; j < vectorBytes(d); j++ {
			switch op {
			case opbsl:
				out[j] = (old[j] & x[j]) | (^old[j] & y[j])
			case opbit:
				out[j] = (old[j] &^ y[j]) | (x[j] & y[j])
			case opbif:
				out[j] = (old[j] & y[j]) | (x[j] &^ y[j])
			}
		}
		c.V[d.Reg-64] = out
		return
	}
	if op == optbl || op == optbx {
		if op == optbx {
			copy(out[:vectorBytes(d)], c.V[d.Reg-64][:vectorBytes(d)])
		}
		var table [64]byte
		size := 0
		for _, s := range a[1 : len(a)-1] {
			copy(table[size:size+16], c.V[s.Reg-64][:])
			size += 16
		}
		idx := c.V[a[len(a)-1].Reg-64]
		for j := 0; j < vectorBytes(d); j++ {
			if int(idx[j]) < size {
				out[j] = table[idx[j]]
			}
		}
		c.V[d.Reg-64] = out
		return
	}
	if op == opext {
		var cat [32]byte
		count := vectorBytes(d)
		copy(cat[:count], c.V[a[1].Reg-64][:])
		copy(cat[count:count*2], c.V[a[2].Reg-64][:])
		offset := int(c.value(a[3]))
		copy(out[:count], cat[offset:offset+count])
		c.V[d.Reg-64] = out
		return
	}
	if op == opzip1 || op == opzip2 || op == opuzp1 || op == opuzp2 || op == optrn1 || op == optrn2 {
		for j := uint8(0); j < n; j++ {
			s, l := a[1], j
			switch op {
			case opzip1, opzip2:
				l = j / 2
				if op == opzip2 {
					l += n / 2
				}
				if j%2 != 0 {
					s = a[2]
				}
			case opuzp1, opuzp2:
				l = (j % (n / 2)) * 2
				if op == opuzp2 {
					l++
				}
				if j >= n/2 {
					s = a[2]
				}
			case optrn1, optrn2:
				l = (j / 2) * 2
				if op == optrn2 {
					l++
				}
				if j%2 != 0 {
					s = a[2]
				}
			}
			lanePut(&out, j, w, c.lane(s, l))
		}
		c.V[d.Reg-64] = out
		return
	}
	if op == oprev16 || op == oprev32 || op == oprev64 {
		group := uint8(16) / w
		if op == oprev32 {
			group = 32 / w
		}
		if op == oprev64 {
			group = 64 / w
		}
		for j := uint8(0); j < n; j++ {
			lanePut(&out, j, w, c.lane(a[1], (j/group)*group+group-1-j%group))
		}
		c.V[d.Reg-64] = out
		return
	}
	if op == opaddv || op == opuaddlv || op == opsaddlv {
		var sum uint64
		for j := uint8(0); j < laneCount(a[1]); j++ {
			x := c.lane(a[1], j)
			if op == opsaddlv {
				x = uint64(signed(x, a[1].Width))
			}
			sum += x
		}
		lanePut(&out, 0, w, sum)
		c.V[d.Reg-64] = out
		return
	}
	narrow := op == opxtn || op == opxtn2 || op == opuqxtn || op == opuqxtn2 || op == opsqxtn || op == opsqxtn2 || op == opshrn || op == opshrn2
	highNarrow := op == opxtn2 || op == opuqxtn2 || op == opsqxtn2 || op == opshrn2
	start := uint8(0)
	if narrow {
		n = laneCount(a[1])
		if highNarrow {
			out = c.V[d.Reg-64]
			start = n
		}
	}
	for j := uint8(0); j < n; j++ {
		var x, y, z, v uint64
		srcLane := j
		switch op {
		case opushll2, opsshll2, opshll2, opumull2, opsmull2, opumlal2, opsmlal2, opumlsl2, opsmlsl2:
			srcLane += n
		}
		if len(a) > 1 {
			x = c.lane(a[1], srcLane)
		}
		if len(a) > 2 {
			y = c.lane(a[2], srcLane)
		}
		z = laneGet(c.V[d.Reg-64], j, w)
		switch op {
		case opdup:
			v = c.lane(a[1], 0)
		case opmovi:
			v = c.value(a[1])
		case opmvni:
			v = ^c.value(a[1])
		case opand:
			v = x & y
		case oporr:
			if len(a) == 2 {
				v = z | x
			} else {
				v = x | y
			}
		case opeor:
			v = x ^ y
		case opbic:
			if len(a) == 2 {
				v = z &^ x
			} else {
				v = x &^ y
			}
		case oporn:
			v = x | ^y
		case opmvn:
			v = ^x
		case opadd:
			v = x + y
		case opsub:
			v = x - y
		case opneg:
			v = -x
		case opmul:
			v = x * y
		case opmla:
			v = z + x*y
		case opmls:
			v = z - x*y
		case opclz:
			v = uint64(bits.LeadingZeros64(x)) - uint64(64-w)
		case oprbit:
			v = bits.Reverse64(x) >> (64 - w)
		case opcmeq:
			if x == y {
				v = mask(w)
			}
		case opcmgt:
			if signed(x, w) > signed(y, w) {
				v = mask(w)
			}
		case opcmge:
			if signed(x, w) >= signed(y, w) {
				v = mask(w)
			}
		case opcmhi:
			if x > y {
				v = mask(w)
			}
		case opcmhs:
			if x >= y {
				v = mask(w)
			}
		case opcmtst:
			if x&y != 0 {
				v = mask(w)
			}
		case opshl, opushll, opushll2, opshll, opshll2:
			v = x << y
		case opsshll, opsshll2:
			v = uint64(signed(x, a[1].Width)) << y
		case opushr:
			v = x >> y
		case opsshr:
			v = uint64(signed(x, w) >> y)
		case opusra:
			v = z + (x >> y)
		case opssra:
			v = z + uint64(signed(x, w)>>y)
		case opsli:
			v = (z & mask(uint8(y))) | (x << y)
		case opsri:
			v = (z &^ mask(w-uint8(y))) | (x >> y)
		case opushl, opsshl:
			shift := int8(y)
			if shift >= 0 {
				v = x << uint8(shift)
			} else if op == opsshl {
				v = uint64(signed(x, w) >> uint8(-int16(shift)))
			} else {
				v = x >> uint8(-int16(shift))
			}
		case opxtn, opxtn2:
			v = x
		case opshrn, opshrn2:
			v = x >> y
		case opuqxtn, opuqxtn2:
			v = min(x, mask(w))
		case opsqxtn, opsqxtn2:
			v = uint64(max(-(int64(1) << (w - 1)), min(signed(x, a[1].Width), (int64(1)<<(w-1))-1)))
		case opumull, opumull2:
			v = x * y
		case opsmull, opsmull2:
			v = uint64(signed(x, a[1].Width) * signed(y, a[2].Width))
		case opumlal, opumlal2:
			v = z + x*y
		case opsmlal, opsmlal2:
			v = z + uint64(signed(x, a[1].Width)*signed(y, a[2].Width))
		case opumlsl, opumlsl2:
			v = z - x*y
		case opsmlsl, opsmlsl2:
			v = z - uint64(signed(x, a[1].Width)*signed(y, a[2].Width))
		case opuaddw, opuaddw2:
			l := j
			if op == opuaddw2 {
				l += n
			}
			v = x + c.lane(a[2], l)
		case opuaddlp, opsaddlp, opuadalp, opsadalp:
			x, y = c.lane(a[1], j*2), c.lane(a[1], j*2+1)
			if op == opsaddlp || op == opsadalp {
				x = uint64(signed(x, a[1].Width))
				y = uint64(signed(y, a[1].Width))
			}
			v = x + y
			if op == opuadalp || op == opsadalp {
				v += z
			}
		case opfneg:
			v = x ^ (uint64(1) << (w - 1))
		case opfadd, opfsub, opfmul, opfdiv:
			f, g := math.Float64frombits(x), math.Float64frombits(y)
			if w == 32 {
				f, g = float64(math.Float32frombits(uint32(x))), float64(math.Float32frombits(uint32(y)))
			}
			switch op {
			case opfadd:
				f += g
			case opfsub:
				f -= g
			case opfmul:
				f *= g
			case opfdiv:
				f /= g
			}
			v = math.Float64bits(f)
			if w == 32 {
				v = uint64(math.Float32bits(float32(f)))
			}
		case opfcvt:
			if w == 32 {
				v = uint64(math.Float32bits(float32(math.Float64frombits(x))))
			} else {
				v = math.Float64bits(float64(math.Float32frombits(uint32(x))))
			}
		case opscvtf, opucvtf:
			f := float64(x)
			if op == opscvtf {
				f = float64(signed(x, a[1].Width))
			}
			v = math.Float64bits(f)
			if w == 32 {
				v = uint64(math.Float32bits(float32(f)))
			}
		default:
			m.fail(i)
		}
		lanePut(&out, j+start, w, v)
	}
	c.V[d.Reg-64] = out
}
func (m *Machine) structureOp(i instruction, a []operand) {
	c := &m.CPU
	mi := 0
	for mi < len(a) && a[mi].Kind != 3 {
		mi++
	}
	if mi == len(a) {
		m.fail(i)
	}
	address := m.address(a[mi])
	op := i.Op
	load := op == opld1 || op == opld2 || op == opld3 || op == opld4 || op == opld1r
	count := 1
	switch op {
	case opld2, opst2:
		count = 2
	case opld3, opst3:
		count = 3
	case opld4, opst4:
		count = 4
	}
	pos := address
	if count > 1 {
		for j := uint8(0); j < laneCount(a[0]); j++ {
			for k := 0; k < mi; k++ {
				o := a[k]
				l := j
				if o.Lane != 255 {
					l = o.Lane
				}
				if load {
					lanePut(&c.V[o.Reg-64], l, o.Width, m.Memory.Get(pos, o.Width))
				} else {
					m.Memory.Put(pos, c.lane(o, l), o.Width)
				}
				pos += uint64(o.Width / 8)
			}
		}
	} else {
		for _, o := range a[:mi] {
			if o.Lane != 255 {
				if load {
					lanePut(&c.V[o.Reg-64], o.Lane, o.Width, m.Memory.Get(pos, o.Width))
				} else {
					m.Memory.Put(pos, c.lane(o, 0), o.Width)
				}
				pos += uint64(o.Width / 8)
				continue
			}
			if load {
				c.V[o.Reg-64] = [16]byte{}
			}
			if op == opld1r {
				v := m.Memory.Get(pos, o.Width)
				for j := uint8(0); j < laneCount(o); j++ {
					lanePut(&c.V[o.Reg-64], j, o.Width, v)
				}
				pos += uint64(o.Width / 8)
				continue
			}
			size := uint64(vectorBytes(o))
			if load {
				copy(c.V[o.Reg-64][:], m.Memory.Slice(pos, size))
			} else {
				m.Memory.Write(pos, c.V[o.Reg-64][:size])
			}
			pos += size
		}
	}
	if i.Flags&1 != 0 {
		if len(a) > mi+1 {
			pos = address + c.value(a[mi+1])
		}
		c.writeReg(a[mi].Reg, 64, pos)
	}
}
func (m *Machine) floatCompare(i instruction, a []operand) {
	c := &m.CPU
	x := c.lane(a[0], 0)
	y := c.lane(a[1], 0)
	f, g := math.Float64frombits(x), math.Float64frombits(y)
	if a[0].Width == 32 {
		f, g = float64(math.Float32frombits(uint32(x))), float64(math.Float32frombits(uint32(y)))
	}
	switch {
	case math.IsNaN(f) || math.IsNaN(g):
		c.NZCV = 3 << 28
	case f == g:
		c.NZCV = 6 << 28
	case f < g:
		c.NZCV = 8 << 28
	default:
		c.NZCV = 2 << 28
	}
}
func (m *Machine) floatConvert(i instruction, a []operand) {
	if i.Op != opfcvtzs && i.Op != opfcvtzu {
		m.fail(i)
	}
	c := &m.CPU
	x := c.lane(a[1], 0)
	f := math.Float64frombits(x)
	if a[1].Width == 32 {
		f = float64(math.Float32frombits(uint32(x)))
	}
	var v uint64
	if !math.IsNaN(f) {
		if i.Op == opfcvtzs {
			lo, hi := -math.Ldexp(1, int(a[0].Width)-1), math.Ldexp(1, int(a[0].Width)-1)
			if f <= lo {
				v = uint64(1) << (a[0].Width - 1)
			} else if f >= hi {
				v = (uint64(1) << (a[0].Width - 1)) - 1
			} else {
				v = uint64(int64(f))
			}
		} else if f > 0 {
			if f >= math.Ldexp(1, int(a[0].Width)) {
				v = mask(a[0].Width)
			} else {
				v = uint64(f)
			}
		}
	}
	c.writeReg(a[0].Reg, a[0].Width, v)
}
