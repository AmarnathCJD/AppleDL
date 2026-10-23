package applemusic

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"sync/atomic"
)

var errALAC = errors.New("invalid or unsupported ALAC fragment structure")

type alacBox struct {
	kind                string
	start, payload, end int
}

func alacBoxes(data []byte, start, end int) ([]alacBox, error) {
	var boxes []alacBox
	if start < 0 || end > len(data) || start > end {
		return nil, errALAC
	}
	for start < end {
		if end-start < 8 || len(boxes) >= 10000 {
			return nil, errALAC
		}
		n, header := uint64(binary.BigEndian.Uint32(data[start:])), 8
		if n == 1 {
			if end-start < 16 {
				return nil, errALAC
			}
			n, header = binary.BigEndian.Uint64(data[start+8:]), 16
		}
		if n == 0 {
			n = uint64(end - start)
		}
		if n < uint64(header) || n > uint64(end-start) {
			return nil, errALAC
		}
		boxes = append(boxes, alacBox{string(data[start+4 : start+8]), start, start + header, start + int(n)})
		start += int(n)
	}
	return boxes, nil
}

func alacChild(data []byte, parent alacBox, kind string) (alacBox, error) {
	boxes, err := alacBoxes(data, parent.payload, parent.end)
	if err != nil {
		return alacBox{}, err
	}
	var result alacBox
	for _, box := range boxes {
		if box.kind == kind {
			if result.end != 0 {
				return alacBox{}, errALAC
			}
			result = box
		}
	}
	if result.end == 0 {
		return alacBox{}, errALAC
	}
	return result, nil
}

func alacPath(data []byte, kinds ...string) (alacBox, error) {
	b := alacBox{end: len(data)}
	var err error
	for _, kind := range kinds {
		b, err = alacChild(data, b, kind)
		if err != nil {
			return b, err
		}
	}
	return b, nil
}

func alacFree(data []byte, box alacBox) {
	copy(data[box.start+4:box.start+8], "free")
	clear(data[box.payload:box.end])
}

// ALACInitialization describes the supported single-track fragmented ALAC
// layout. Protection data stays private and is erased from ClearInitialization.
// Other CENC layouts are rejected; this is not a general MP4 demuxer.
type ALACInitialization struct {
	TrackID, Timescale, DescriptionCount uint32
	Configuration                        MP4ALACConfiguration
	description, duration, size          uint32
	clearInit                            []byte
}

func (a *ALACInitialization) ClearInitialization() []byte { return bytes.Clone(a.clearInit) }

func ParseALACInitialization(data []byte) (*ALACInitialization, error) {
	if len(data) < 8 || int64(len(data)) > MaxHLSResourceBytes {
		return nil, errALAC
	}
	// The inspector bounds nesting and validates audio/tenc field sizes.
	inspection, err := InspectMP4(data)
	if err != nil || inspection.Boxes["trak"] != 1 || inspection.Boxes["stsd"] != 1 || inspection.Boxes["trex"] != 1 || inspection.Boxes["mdat"] != 0 {
		return nil, errALAC
	}
	tkhd, err := alacPath(data, "moov", "trak", "tkhd")
	if err != nil {
		return nil, err
	}
	mdhd, err := alacPath(data, "moov", "trak", "mdia", "mdhd")
	if err != nil {
		return nil, err
	}
	field := func(b alacBox) (uint32, error) {
		p := data[b.payload:b.end]
		offset := 12
		if len(p) < 4 || p[0] > 1 {
			return 0, errALAC
		}
		if p[0] == 1 {
			offset = 20
		}
		if len(p) < offset+4 {
			return 0, errALAC
		}
		return binary.BigEndian.Uint32(p[offset:]), nil
	}
	a := &ALACInitialization{}
	a.TrackID, err = field(tkhd)
	if err != nil || a.TrackID == 0 {
		return nil, errALAC
	}
	a.Timescale, err = field(mdhd)
	if err != nil || a.Timescale == 0 {
		return nil, errALAC
	}
	trex, err := alacPath(data, "moov", "mvex", "trex")
	if err != nil {
		return nil, err
	}
	p := data[trex.payload:trex.end]
	if len(p) != 24 || binary.BigEndian.Uint32(p) != 0 || binary.BigEndian.Uint32(p[4:]) != a.TrackID {
		return nil, errALAC
	}
	a.description, a.duration, a.size = binary.BigEndian.Uint32(p[8:]), binary.BigEndian.Uint32(p[12:]), binary.BigEndian.Uint32(p[16:])
	stsd, err := alacPath(data, "moov", "trak", "mdia", "minf", "stbl", "stsd")
	if err != nil {
		return nil, err
	}
	p = data[stsd.payload:stsd.end]
	if len(p) < 8 || binary.BigEndian.Uint32(p) != 0 {
		return nil, errALAC
	}
	a.DescriptionCount = binary.BigEndian.Uint32(p[4:])
	entries, err := alacBoxes(data, stsd.payload+8, stsd.end)
	if err != nil || len(entries) == 0 || len(entries) > 16 || uint32(len(entries)) != a.DescriptionCount || a.description == 0 || a.description > a.DescriptionCount {
		return nil, errALAC
	}
	clearInit := bytes.Clone(data)
	var firstConfig []byte
	for _, entry := range entries {
		if entry.kind != "enca" || entry.end-entry.payload < 28 || binary.BigEndian.Uint16(data[entry.payload+8:]) != 0 {
			return nil, errALAC
		}
		children := alacBox{payload: entry.payload + 28, end: entry.end}
		config, e := alacChild(data, children, "alac")
		if e != nil {
			return nil, e
		}
		p = data[config.payload:config.end]
		if len(p) != 28 || binary.BigEndian.Uint32(p) != 0 {
			return nil, errALAC
		}
		if firstConfig == nil {
			firstConfig = p
		} else if !bytes.Equal(firstConfig, p) {
			return nil, errALAC
		}
		a.Configuration = MP4ALACConfiguration{FrameSamples: binary.BigEndian.Uint32(p[4:]), BitDepth: p[9], Channels: p[13], SampleRate: binary.BigEndian.Uint32(p[24:])}
		if a.Configuration.FrameSamples == 0 || a.Configuration.FrameSamples > 65536 || a.Configuration.SampleRate != a.Timescale || a.Configuration.Channels == 0 || a.Configuration.Channels > 8 || (a.Configuration.BitDepth != 16 && a.Configuration.BitDepth != 24 && a.Configuration.BitDepth != 32) {
			return nil, errALAC
		}
		sinf, e := alacChild(data, children, "sinf")
		if e != nil {
			return nil, e
		}
		frma, e := alacChild(data, sinf, "frma")
		if e != nil || string(data[frma.payload:frma.end]) != "alac" {
			return nil, errALAC
		}
		schm, e := alacChild(data, sinf, "schm")
		if e != nil {
			return nil, e
		}
		p = data[schm.payload:schm.end]
		if len(p) != 12 || binary.BigEndian.Uint32(p) != 0 || string(p[4:8]) != "cbcs" {
			return nil, errALAC
		}
		schi, e := alacChild(data, sinf, "schi")
		if e != nil {
			return nil, e
		}
		tenc, e := alacChild(data, schi, "tenc")
		if e != nil {
			return nil, e
		}
		p = data[tenc.payload:tenc.end]
		// APK ALAC Pastis mode 5 consumes complete access units and the
		// native license context supplies crypto state. No IV/key extraction.
		if len(p) != 41 || binary.BigEndian.Uint32(p) != 0x01000000 || p[4] != 0 || p[5] != 0 || p[6] != 1 || p[7] != 0 || p[24] != 16 {
			return nil, errALAC
		}
		copy(clearInit[entry.start+4:entry.start+8], "alac")
		alacFree(clearInit, sinf)
	}
	a.clearInit = clearInit
	return a, nil
}

type ALACSample struct {
	Offset         int
	Size, Duration uint32
}

type ALACFragment struct {
	DescriptionIndex     uint32
	DecodeTime, Duration uint64
	Samples              []ALACSample
	auxiliary            []alacBox
}

// ParseALACFragment resolves trun offsets against its moof, applies trex/tfhd
// defaults, and validates all sample and auxiliary ranges before decryption.
// Supported: one moof/traf/trun/mdat, default-base-is-moof, no sample groups,
// constant IV, one whole-sample encrypted subsample per ALAC access unit.
func ParseALACFragment(data []byte, init *ALACInitialization) (*ALACFragment, error) {
	if init == nil || len(data) < 8 || int64(len(data)) > MaxHLSResourceBytes {
		return nil, errALAC
	}
	top, err := alacBoxes(data, 0, len(data))
	if err != nil {
		return nil, err
	}
	var moof, mdat alacBox
	for _, b := range top {
		switch b.kind {
		case "moof":
			if moof.end != 0 {
				return nil, errALAC
			}
			moof = b
		case "mdat":
			if mdat.end != 0 {
				return nil, errALAC
			}
			mdat = b
		case "styp", "free", "sidx":
		default:
			return nil, errALAC
		}
	}
	if moof.end == 0 || mdat.end == 0 {
		return nil, errALAC
	}
	traf, err := alacChild(data, moof, "traf")
	if err != nil {
		return nil, err
	}
	children, err := alacBoxes(data, traf.payload, traf.end)
	if err != nil {
		return nil, err
	}
	byName := map[string]alacBox{}
	for _, b := range children {
		switch b.kind {
		case "tfhd", "tfdt", "trun", "senc", "saiz", "saio":
			if byName[b.kind].end != 0 {
				return nil, errALAC
			}
			byName[b.kind] = b
		case "free":
		default:
			return nil, errALAC
		}
	}
	for _, kind := range []string{"tfhd", "tfdt", "trun", "senc", "saiz", "saio"} {
		if byName[kind].end == 0 {
			return nil, errALAC
		}
	}
	payload := func(kind string) []byte { b := byName[kind]; return data[b.payload:b.end] }
	p := payload("tfhd")
	if len(p) < 8 || p[0] != 0 {
		return nil, errALAC
	}
	flags := binary.BigEndian.Uint32(p) & 0xffffff
	if flags&0x20000 == 0 || flags & ^uint32(0x2003a) != 0 || binary.BigEndian.Uint32(p[4:]) != init.TrackID {
		return nil, errALAC
	}
	f := &ALACFragment{DescriptionIndex: init.description}
	duration, size := init.duration, init.size
	pos := 8
	read := func() (uint32, bool) {
		if len(p)-pos < 4 {
			return 0, false
		}
		v := binary.BigEndian.Uint32(p[pos:])
		pos += 4
		return v, true
	}
	for _, field := range []struct {
		flag  uint32
		value *uint32
	}{{2, &f.DescriptionIndex}, {8, &duration}, {16, &size}, {32, new(uint32)}} {
		if flags&field.flag != 0 {
			var ok bool
			*field.value, ok = read()
			if !ok {
				return nil, errALAC
			}
		}
	}
	if pos != len(p) || f.DescriptionIndex == 0 || f.DescriptionIndex > init.DescriptionCount {
		return nil, errALAC
	}
	p = payload("tfdt")
	if len(p) < 4 || p[0] > 1 || binary.BigEndian.Uint32(p)&0xffffff != 0 {
		return nil, errALAC
	}
	if p[0] == 0 {
		if len(p) != 8 {
			return nil, errALAC
		}
		f.DecodeTime = uint64(binary.BigEndian.Uint32(p[4:]))
	} else {
		if len(p) != 12 {
			return nil, errALAC
		}
		f.DecodeTime = binary.BigEndian.Uint64(p[4:])
	}
	p = payload("trun")
	if len(p) < 12 || p[0] > 1 {
		return nil, errALAC
	}
	flags = binary.BigEndian.Uint32(p) & 0xffffff
	// Audio composition-time offsets and conflicting first/sample flags are unsupported.
	if flags&1 == 0 || flags & ^uint32(0x705) != 0 || flags&0x404 == 0x404 {
		return nil, errALAC
	}
	n := binary.BigEndian.Uint32(p[4:])
	if n == 0 || n > 100000 {
		return nil, errALAC
	}
	offset := int64(moof.start) + int64(int32(binary.BigEndian.Uint32(p[8:])))
	pos = 12
	if flags&4 != 0 {
		if _, ok := read(); !ok {
			return nil, errALAC
		}
	}
	for i := uint32(0); i < n; i++ {
		d, s := duration, size
		if flags&0x100 != 0 {
			var ok bool
			d, ok = read()
			if !ok {
				return nil, errALAC
			}
		}
		if flags&0x200 != 0 {
			var ok bool
			s, ok = read()
			if !ok {
				return nil, errALAC
			}
		}
		if flags&0x400 != 0 {
			if _, ok := read(); !ok {
				return nil, errALAC
			}
		}
		if d == 0 || d > init.Configuration.FrameSamples || s == 0 || s > 4<<20 || offset < int64(mdat.payload) || offset+int64(s) > int64(mdat.end) {
			return nil, errALAC
		}
		f.Samples = append(f.Samples, ALACSample{int(offset), s, d})
		f.Duration += uint64(d)
		offset += int64(s)
	}
	if pos != len(p) || f.Samples[0].Offset != mdat.payload || offset != int64(mdat.end) || math.MaxUint64-f.DecodeTime < f.Duration {
		return nil, errALAC
	}
	p = payload("senc")
	if len(p) != 8+int(n)*8 || binary.BigEndian.Uint32(p) != 2 || binary.BigEndian.Uint32(p[4:]) != n {
		return nil, errALAC
	}
	for i, s := range f.Samples {
		entry := p[8+i*8:]
		if binary.BigEndian.Uint16(entry) != 1 || binary.BigEndian.Uint16(entry[2:]) != 0 || binary.BigEndian.Uint32(entry[4:]) != s.Size {
			return nil, errALAC
		}
	}
	p = payload("saiz")
	if len(p) < 9 || binary.BigEndian.Uint32(p) != 0 || binary.BigEndian.Uint32(p[5:]) != n {
		return nil, errALAC
	}
	if p[4] == 0 {
		if len(p) != 9+int(n) {
			return nil, errALAC
		}
		for _, s := range p[9:] {
			if s != 8 {
				return nil, errALAC
			}
		}
	} else if p[4] != 8 || len(p) != 9 {
		return nil, errALAC
	}
	p = payload("saio")
	if len(p) < 8 || p[0] > 1 || binary.BigEndian.Uint32(p)&0xffffff != 0 || binary.BigEndian.Uint32(p[4:]) != 1 {
		return nil, errALAC
	}
	var auxOffset uint64
	if p[0] == 0 {
		if len(p) != 12 {
			return nil, errALAC
		}
		auxOffset = uint64(binary.BigEndian.Uint32(p[8:]))
	} else {
		if len(p) != 16 {
			return nil, errALAC
		}
		auxOffset = binary.BigEndian.Uint64(p[8:])
	}
	if auxOffset != uint64(byName["senc"].payload+8-moof.start) {
		return nil, errALAC
	}
	f.auxiliary = []alacBox{byName["senc"], byName["saiz"], byName["saio"]}
	return f, nil
}

// DecryptALACFragment invokes the supplied licensed decryptor once per
// complete ALAC sample. It preserves offsets and timing and erases encryption
// boxes only after every sample succeeds. Decode validation remains separate.
func DecryptALACFragment(ctx context.Context, data []byte, init *ALACInitialization, decrypt func(context.Context, []byte) ([]byte, error)) ([]byte, *ALACFragment, error) {
	return DecryptALACFragmentParallel(ctx, data, init, decrypt)
}

// DecryptALACFragmentParallel uses one independent decryptor per worker. Each
// callback is called sequentially, while different callbacks may run in parallel.
// Samples have validated, disjoint output ranges; file order is preserved.
// A failure cancels the other workers and erases partial output before returning.
func DecryptALACFragmentParallel(ctx context.Context, data []byte, init *ALACInitialization, decryptors ...func(context.Context, []byte) ([]byte, error)) ([]byte, *ALACFragment, error) {
	if len(decryptors) == 0 || len(decryptors) > 64 {
		return nil, nil, errALAC
	}
	for _, decrypt := range decryptors {
		if decrypt == nil {
			return nil, nil, errALAC
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	f, err := ParseALACFragment(data, init)
	if err != nil {
		return nil, nil, err
	}
	out := bytes.Clone(data)
	workCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var next atomic.Int64
	work := func(decrypt func(context.Context, []byte) ([]byte, error)) {
		for workCtx.Err() == nil {
			i := int(next.Add(1) - 1)
			if i >= len(f.Samples) {
				return
			}
			s := f.Samples[i]
			input := bytes.Clone(data[s.Offset : s.Offset+int(s.Size)])
			part, e := decrypt(workCtx, input)
			if e == nil && len(part) != int(s.Size) {
				e = errors.New("ALAC decryptor returned an invalid sample size")
			}
			if e == nil {
				copy(out[s.Offset:s.Offset+int(s.Size)], part)
			}
			clear(input)
			clear(part)
			if e != nil {
				cancel(e)
				return
			}
		}
	}
	if len(decryptors) == 1 {
		work(decryptors[0])
	} else {
		var wg sync.WaitGroup
		for _, decrypt := range decryptors[:min(len(decryptors), len(f.Samples))] {
			wg.Go(func() { work(decrypt) })
		}
		wg.Wait()
	}
	if err := context.Cause(workCtx); err != nil {
		clear(out)
		return nil, nil, err
	}
	for _, b := range f.auxiliary {
		alacFree(out, b)
	}
	return out, f, nil
}
