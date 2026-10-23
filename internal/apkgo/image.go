// Package apkgo executes build-time lowered APK operations entirely in Go.
// It never loads shared libraries, decodes ARM instructions, or executes JIT code.
package apkgo

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

//go:embed images/*.ir.gz
var images embed.FS

type Relocation struct {
	Address uint64
	Symbol  string
	Addend  uint64
}

func (r *Relocation) UnmarshalJSON(b []byte) error {
	var a []json.RawMessage
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	if len(a) != 3 {
		return errors.New("invalid relocation")
	}
	if err := json.Unmarshal(a[0], &r.Address); err != nil {
		return err
	}
	if err := json.Unmarshal(a[1], &r.Symbol); err != nil {
		return err
	}
	var n int64
	if err := json.Unmarshal(a[2], &n); err != nil {
		return err
	}
	r.Addend = uint64(n)
	return nil
}

type metadata struct {
	Name, Hash string
	Exports    map[string]uint64
	Relocs     []Relocation
	Init       [2]uint64
	Ops        []string
}
type Segment struct {
	Address, Size uint64
	Data          []byte
}
type instruction struct {
	Offset           uint32
	Op               uint16
	CC, Flags, Count uint8
}
type operand struct {
	Value                                             uint64
	Kind, Reg, Width, Lanes, Lane, Ext, Shift, Amount uint8
}
type section struct {
	Address uint64
	Code    []instruction
	Args    []operand
}
type Image struct {
	metadata
	Segments []Segment
	sections []section
}

var imageCache sync.Map
var imageMu sync.Mutex

func Load(name string) (result *Image, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = errors.New("translated image is incomplete or invalid")
		}
	}()
	if i, ok := imageCache.Load(name); ok {
		return i.(*Image), nil
	}
	imageMu.Lock()
	defer imageMu.Unlock()
	if i, ok := imageCache.Load(name); ok {
		return i.(*Image), nil
	}
	if len(name) < 4 || name[len(name)-3:] != ".so" {
		return nil, errors.New("unknown translated image")
	}
	compressed, err := images.ReadFile("images/" + name[:len(name)-3] + ".ir.gz")
	if err != nil {
		return nil, errors.New("translated image unavailable")
	}
	z, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer z.Close()
	r := bufio.NewReaderSize(io.LimitReader(z, 1<<30), 256<<10)
	get := func(n uint32) []byte {
		if n > 128<<20 {
			panic("translated image bound")
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			panic("truncated translated image")
		}
		return b
	}
	u32 := func() uint32 { return binary.LittleEndian.Uint32(get(4)) }
	blob := func() []byte { return get(u32()) }
	if string(get(8)) != "AMGOIR01" {
		return nil, errors.New("translated image format")
	}
	i := &Image{}
	if err = json.Unmarshal(blob(), &i.metadata); err != nil {
		return nil, err
	}
	if len(i.Ops) != len(opNames) {
		return nil, errors.New("translated operation version mismatch")
	}
	for n, v := range i.Ops {
		if v != opNames[n] {
			return nil, errors.New("translated operation table mismatch")
		}
	}
	for n := u32(); n > 0; n-- {
		b := get(16)
		i.Segments = append(i.Segments, Segment{binary.LittleEndian.Uint64(b), binary.LittleEndian.Uint64(b[8:]), blob()})
	}
	for n := u32(); n > 0; n-- {
		b := get(12)
		s := section{Address: binary.LittleEndian.Uint64(b), Code: make([]instruction, binary.LittleEndian.Uint32(b[8:]))}
		for k := range s.Code {
			b = get(5)
			ins := instruction{Op: binary.LittleEndian.Uint16(b), CC: b[2], Flags: b[3], Count: b[4], Offset: uint32(len(s.Args))}
			if ins.Count > 6 || int(ins.Op) >= len(opNames) {
				return nil, errors.New("translated operation invalid")
			}
			b = get(uint32(ins.Count) * 16)
			for j := 0; j < len(b); j += 16 {
				v := b[j : j+16]
				s.Args = append(s.Args, operand{binary.LittleEndian.Uint64(v[8:]), v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]})
			}
			s.Code[k] = ins
		}
		i.sections = append(i.sections, s)
	}
	imageCache.Store(name, i)
	return i, nil
}

type region struct {
	start uint64
	data  []byte
}
type Memory struct {
	regions []region
	last    int
}

func (m *Memory) Map(address, size uint64) {
	if size == 0 || size > 256<<20 || address+size < address {
		panic("Go memory map bound")
	}
	for _, r := range m.regions {
		if address < r.start+uint64(len(r.data)) && r.start < address+size {
			panic("Go memory map overlaps")
		}
	}
	m.regions = append(m.regions, region{address, make([]byte, size)})
}
func (m *Memory) Slice(address, size uint64) []byte {
	if address+size < address {
		panic("Go memory address overflow")
	}
	if len(m.regions) > 0 {
		r := &m.regions[m.last]
		if address >= r.start && address+size <= r.start+uint64(len(r.data)) {
			return r.data[address-r.start : address-r.start+size]
		}
	}
	for k := range m.regions {
		r := &m.regions[k]
		if address >= r.start && address+size <= r.start+uint64(len(r.data)) {
			m.last = k
			return r.data[address-r.start : address-r.start+size]
		}
	}
	panic("Go memory address unmapped")
}
func (m *Memory) Read(address, size uint64) []byte { return bytes.Clone(m.Slice(address, size)) }
func (m *Memory) Write(address uint64, b []byte)   { copy(m.Slice(address, uint64(len(b))), b) }
func (m *Memory) Get(address uint64, width uint8) uint64 {
	b := m.Slice(address, uint64(width/8))
	switch width {
	case 8:
		return uint64(b[0])
	case 16:
		return uint64(binary.LittleEndian.Uint16(b))
	case 32:
		return uint64(binary.LittleEndian.Uint32(b))
	case 64:
		return binary.LittleEndian.Uint64(b)
	}
	panic("Go load width")
}
func (m *Memory) Put(address, value uint64, width uint8) {
	b := m.Slice(address, uint64(width/8))
	switch width {
	case 8:
		b[0] = byte(value)
	case 16:
		binary.LittleEndian.PutUint16(b, uint16(value))
	case 32:
		binary.LittleEndian.PutUint32(b, uint32(value))
	case 64:
		binary.LittleEndian.PutUint64(b, value)
	default:
		panic("Go store width")
	}
}
func (m *Memory) Close() {
	for _, r := range m.regions {
		clear(r.data)
	}
	m.regions = nil
}

type CPU struct {
	R                    [33]uint64
	V                    [32][16]byte
	PC, TLS, NZCV, CPACR uint64
	Exclusive            uint64
}
type loadedImage struct {
	base  uint64
	image *Image
}
type Machine struct {
	CPU      CPU
	Memory   Memory
	loaded   []loadedImage
	current  *section
	codeBase uint64
	Hook     func(uint64)
	Import   func(uint64)
	Stop     bool
	Steps    uint64
}

func (m *Machine) Add(i *Image, base uint64) { m.loaded = append(m.loaded, loadedImage{base, i}) }
func (m *Machine) instruction() (instruction, []operand) {
	pc := m.CPU.PC
	if m.current != nil && pc >= m.codeBase && (pc-m.codeBase)/4 < uint64(len(m.current.Code)) {
		in := m.current.Code[(pc-m.codeBase)/4]
		return in, m.current.Args[in.Offset : in.Offset+uint32(in.Count)]
	}
	for _, l := range m.loaded {
		for k := range l.image.sections {
			s := &l.image.sections[k]
			base := l.base + s.Address
			if pc >= base && (pc-base)/4 < uint64(len(s.Code)) {
				m.current = s
				m.codeBase = base
				in := s.Code[(pc-base)/4]
				return in, s.Args[in.Offset : in.Offset+uint32(in.Count)]
			}
		}
	}
	panic(Fault{PC: pc, Operation: "untranslated address"})
}

type Fault struct {
	PC        uint64
	Operation string
}

func (f Fault) Error() string {
	return fmt.Sprintf("Go translated runtime: %s at code %#x", f.Operation, f.PC)
}
func (m *Machine) Run(end, budget uint64) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if f, ok := r.(Fault); ok {
				err = f
			} else {
				op := "memory or operation failure"
				if s, ok := r.(string); ok {
					op = s
				}
				err = Fault{PC: m.CPU.PC, Operation: op}
			}
		}
	}()
	m.Stop = false
	for n := uint64(0); n < budget && !m.Stop && m.CPU.PC != end; n++ {
		if m.CPU.PC&3 != 0 {
			panic(Fault{m.CPU.PC, "unaligned code"})
		}
		if m.Hook != nil {
			m.Hook(m.CPU.PC)
			if m.Stop || m.CPU.PC == end {
				break
			}
		}
		if m.CPU.PC >= 0x60000000 && m.CPU.PC < 0x60010000 {
			m.Import(m.CPU.PC)
			continue
		}
		// Go implementation of the local pthread_once continuation.
		if m.CPU.PC == 0x70000100 {
			m.once()
			continue
		}
		if m.CPU.PC == 0x70000104 {
			m.onceReturn()
			continue
		}
		i, a := m.instruction()
		m.step(i, a)
		m.Steps++
	}
	return nil
}
func (m *Machine) once() {
	c := &m.CPU
	c.R[32] -= 16
	m.Memory.Put(c.R[32], c.R[19], 64)
	m.Memory.Put(c.R[32]+8, c.R[30], 64)
	c.R[19] = c.R[0]
	c.R[30] = 0x70000104
	c.PC = c.R[1]
}
func (m *Machine) onceReturn() {
	c := &m.CPU
	m.Memory.Put(c.R[19], 2, 32)
	c.R[0] = 0
	c.R[19] = m.Memory.Get(c.R[32], 64)
	c.R[30] = m.Memory.Get(c.R[32]+8, 64)
	c.R[32] += 16
	c.PC = c.R[30]
}
