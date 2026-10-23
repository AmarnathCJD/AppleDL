package standalone

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/AmarnathCJD/AppleDL/internal/envelope"
)

const alacContextImplementation = "6053ef094762a6462812a441d44771574375c11f0ef540a735b86f922725f924:1bfbac-1c4598:v1"

type alacContextPage struct {
	Address uint64 `json:"address"`
	Data    []byte `json:"data"`
}

type alacContextSnapshot struct {
	Version        int               `json:"version"`
	Implementation string            `json:"implementation"`
	Binding        [32]byte          `json:"binding"`
	Buffer         uint64            `json:"buffer"`
	Registers      [32]uint64        `json:"registers"`
	Zero           bool              `json:"zero"`
	StackLow       uint64            `json:"stack_low"`
	StackHigh      uint64            `json:"stack_high"`
	Pages          []alacContextPage `json:"pages"`
}

func (*alacContextSnapshot) String() string   { return "alacContextSnapshot{redacted}" }
func (*alacContextSnapshot) GoString() string { return "alacContextSnapshot{redacted}" }
func (s *alacContextSnapshot) destroy() {
	for _, p := range s.Pages {
		clear(p.Data)
	}
	*s = alacContextSnapshot{}
}

func validALACContext(s *alacContextSnapshot) bool {
	if s.Version != 1 || s.Implementation != alacContextImplementation || s.Binding == [32]byte{} ||
		s.Buffer < heapBase || s.Buffer > heapLimit-alacLoopCapacity ||
		s.StackHigh != arenaBase+0xf0000 || s.StackLow < s.StackHigh-256*1024 ||
		s.StackLow >= s.StackHigh || s.StackLow%16 != 0 || s.Registers[31] != s.StackLow ||
		len(s.Pages) == 0 || len(s.Pages) > 4096 {
		return false
	}
	pages := make(map[uint64]bool, len(s.Pages))
	for _, p := range s.Pages {
		a := p.Address
		if a%alacLoopPageSize != 0 || len(p.Data) != int(alacLoopPageSize) || pages[a] ||
			!(a >= 0x10000000 && a < 0x50000000 || a >= arenaBase && a < heapLimit) {
			return false
		}
		pages[a] = true
	}
	for a := s.Buffer &^ (alacLoopPageSize - 1); a < s.Buffer+alacLoopCapacity; a += alacLoopPageSize {
		if !pages[a] {
			return false
		}
	}
	// Untouched stack pages need not be present. Replay fails on any missing read.
	return true
}

// ExportContext exports portable detached setup tables with a corruption checksum.
// binding must identify the exact ciphertext layout and this context's ordinal.
// This is private licensed state, not a raw AES key. It contains no device login
// session. Anyone with this blob can use it. Caller owns the private blob.
func (d *ALACGoDecryptor) ExportContext(ctx context.Context, binding [32]byte) ([]byte, error) {
	select {
	case d.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-d.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.loop == nil {
		return nil, errors.New("Go ALAC decrypter is closed")
	}
	c := d.loop
	if c.vm != nil || c.memory.read != nil {
		return nil, errors.New("Go ALAC setup is not detached")
	}
	s := &alacContextSnapshot{Version: 1, Implementation: alacContextImplementation, Binding: binding,
		Buffer: c.buffer, Registers: c.state.r, Zero: c.state.zero, StackLow: c.memory.stackLo, StackHigh: c.memory.stackHi}
	defer s.destroy()
	for address, page := range c.memory.initial {
		p := bytes.Clone(page)
		// The reusable input area is overwritten for every sample. Never export it.
		lo, hi := max(address, c.buffer), min(address+alacLoopPageSize, c.buffer+alacLoopCapacity)
		if lo < hi {
			clear(p[lo-address : hi-address])
		}
		s.Pages = append(s.Pages, alacContextPage{Address: address, Data: p})
	}
	sort.Slice(s.Pages, func(i, j int) bool { return s.Pages[i].Address < s.Pages[j].Address })
	if !validALACContext(s) {
		return nil, errors.New("invalid detached ALAC context")
	}
	plain, err := json.Marshal(s)
	defer clear(plain)
	if err != nil || len(plain) > stateLimit-4096 {
		return nil, errors.New("cannot encode ALAC context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return envelope.Encode("AMCTX001", plain, stateLimit)
}

// ImportALACGoDecryptor restores a detached worker without network, device state,
// licensing or native libraries. binding must match the value used at export.
// Close the returned worker when finished. Corrupt or mismatched exports fail.
func ImportALACGoDecryptor(ctx context.Context, blob []byte, binding [32]byte) (*ALACGoDecryptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	invalid := errors.New("invalid ALAC context, binding, implementation")
	plain, err := envelope.Decode("AMCTX001", blob, stateLimit)
	if err != nil {
		return nil, invalid
	}
	defer clear(plain)
	var s alacContextSnapshot
	defer s.destroy()
	if json.Unmarshal(plain, &s) != nil || !validALACContext(&s) || s.Binding != binding {
		return nil, invalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := &alacLoopMemory{initial: make(map[uint64][]byte, len(s.Pages)), dirty: make(map[uint64][]byte),
		stackLo: s.StackLow, stackHi: s.StackHigh, sampleLo: s.Buffer, sampleHi: s.Buffer + alacLoopCapacity}
	for _, p := range s.Pages {
		m.initial[p.Address] = bytes.Clone(p.Data)
	}
	return &ALACGoDecryptor{gate: make(chan struct{}, 1), loop: &alacLoopCapture{buffer: s.Buffer,
		state: alacLoopState{r: s.Registers, zero: s.Zero}, memory: m}, stats: ALACGoStats{SetupPages: len(m.initial)}}, nil
}
