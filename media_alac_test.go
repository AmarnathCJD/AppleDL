package applemusic

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestALACParallelOrderingAndFailure(t *testing.T) {
	init, err := ParseALACInitialization(alacTestInit())
	if err != nil {
		t.Fatal(err)
	}
	data := alacTestFragment()
	serial := func(_ context.Context, p []byte) ([]byte, error) {
		for i := range p {
			p[i] ^= 0xa5
		}
		return p, nil
	}
	want, _, err := DecryptALACFragment(context.Background(), data, init, serial)
	if err != nil {
		t.Fatal(err)
	}
	// Both samples must be in flight together, and the first must finish last.
	second := make(chan struct{})
	var calls atomic.Int32
	parallel := func(ctx context.Context, p []byte) ([]byte, error) {
		if calls.Add(1) == 1 {
			select {
			case <-second:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			close(second)
		}
		return serial(ctx, p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, _, err := DecryptALACFragmentParallel(ctx, data, init, parallel, parallel)
	if err != nil || !bytes.Equal(got, want) || calls.Load() != 2 {
		t.Fatal("parallel output/order mismatch", err)
	}
	failure := errors.New("sample failure")
	started := make(chan struct{})
	waiting := func(ctx context.Context, p []byte) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	failing := func(ctx context.Context, p []byte) ([]byte, error) { <-started; return p, failure }
	got, _, err = DecryptALACFragmentParallel(ctx, data, init, waiting, failing)
	if got != nil || !errors.Is(err, failure) {
		t.Fatal("partial output or wrong cancellation cause", err)
	}
}

func alacTestInit() []byte {
	tkhd, mdhd := make([]byte, 84), make([]byte, 24)
	binary.BigEndian.PutUint32(tkhd[12:], 1)
	binary.BigEndian.PutUint32(mdhd[12:], 48000)
	header := make([]byte, 28)
	binary.BigEndian.PutUint16(header[6:], 1)
	binary.BigEndian.PutUint16(header[16:], 2)
	binary.BigEndian.PutUint16(header[18:], 24)
	binary.BigEndian.PutUint32(header[24:], 48000<<16)
	config := make([]byte, 28)
	binary.BigEndian.PutUint32(config[4:], 4096)
	config[9] = 24
	config[13] = 2
	binary.BigEndian.PutUint32(config[24:], 48000)
	tenc := make([]byte, 41)
	tenc[0] = 1
	tenc[6] = 1
	tenc[24] = 16
	copy(tenc[8:24], "private-key-id!!!")
	copy(tenc[25:], "private-IV-bytes!")
	schm := make([]byte, 12)
	copy(schm[4:], "cbcs")
	entry := mp4Box("enca", header, mp4Box("alac", config), mp4Box("sinf", mp4Box("frma", []byte("alac")), mp4Box("schm", schm), mp4Box("schi", mp4Box("tenc", tenc))))
	stsd := mp4Box("stsd", []byte{0, 0, 0, 0, 0, 0, 0, 2}, entry, entry)
	trex := make([]byte, 24)
	binary.BigEndian.PutUint32(trex[4:], 1)
	binary.BigEndian.PutUint32(trex[8:], 1)
	return mp4Box("moov", mp4Box("trak", mp4Box("tkhd", tkhd), mp4Box("mdia", mp4Box("mdhd", mdhd), mp4Box("minf", mp4Box("stbl", stsd)))), mp4Box("mvex", mp4Box("trex", trex)))
}

func alacTestFragment() []byte {
	u32 := func(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }
	tfhd := mp4Box("tfhd", u32(0x2001a), u32(1), u32(2), u32(4096), u32(19))
	tfdt := mp4Box("tfdt", u32(0x01000000), make([]byte, 8))
	senc := mp4Box("senc", u32(2), u32(2), []byte{0, 1, 0, 0}, u32(19), []byte{0, 1, 0, 0}, u32(21))
	saiz := mp4Box("saiz", u32(0), []byte{8}, u32(2))
	saio := mp4Box("saio", u32(0), u32(1), u32(0))
	trun := mp4Box("trun", u32(0x201), u32(2), u32(0), u32(19), u32(21))
	moof := mp4Box("moof", mp4Box("mfhd", u32(0), u32(1)), mp4Box("traf", tfhd, tfdt, senc, saiz, saio, trun))
	result := append(moof, mp4Box("mdat", bytes.Repeat([]byte{0x71}, 40))...)
	b, _ := alacPath(result, "moof", "traf", "trun")
	binary.BigEndian.PutUint32(result[b.payload+8:], uint32(len(moof)+8))
	b, _ = alacPath(result, "moof", "traf", "senc")
	sencOffset := b.payload + 8
	b, _ = alacPath(result, "moof", "traf", "saio")
	binary.BigEndian.PutUint32(result[b.payload+8:], uint32(sencOffset))
	return result
}

func TestALACDemuxDecryptAndRedaction(t *testing.T) {
	init, err := ParseALACInitialization(alacTestInit())
	if err != nil {
		t.Fatal(err)
	}
	if init.DescriptionCount != 2 || init.TrackID != 1 || init.Timescale != 48000 {
		t.Fatal("initialization mismatch")
	}
	clearInit := init.ClearInitialization()
	if bytes.Contains(clearInit, []byte("private")) || bytes.Contains(clearInit, []byte("enca")) {
		t.Fatal("encryption metadata retained")
	}
	inspection, err := InspectMP4(clearInit)
	if err != nil || len(inspection.TrackEncryption) != 0 || len(inspection.ALACConfigurations) != 2 {
		t.Fatal("invalid clear initialization", err)
	}
	data := alacTestFragment()
	original := bytes.Clone(data)
	f, err := ParseALACFragment(data, init)
	if err != nil {
		t.Fatal(err)
	}
	if f.DescriptionIndex != 2 || len(f.Samples) != 2 || f.Samples[0].Size != 19 || f.Samples[1].Size != 21 || f.Duration != 8192 {
		t.Fatal("sample defaults/description mismatch")
	}
	calls := 0
	plain, _, err := DecryptALACFragment(context.Background(), data, init, func(_ context.Context, s []byte) ([]byte, error) {
		calls++
		for i := range s {
			s[i] = 0x42
		}
		return s, nil
	})
	if err != nil || calls != 2 {
		t.Fatal("decrypt failed", err)
	}
	if !bytes.Equal(original, data) {
		t.Fatal("input mutated")
	}
	for _, s := range f.Samples {
		if !bytes.Equal(plain[s.Offset:s.Offset+int(s.Size)], bytes.Repeat([]byte{0x42}, int(s.Size))) {
			t.Fatal("sample changed after callback")
		}
	}
	for _, b := range f.auxiliary {
		if string(plain[b.start+4:b.start+8]) != "free" || !bytes.Equal(plain[b.payload:b.end], make([]byte, b.end-b.payload)) {
			t.Fatal("auxiliary encryption data retained")
		}
	}
	for _, tc := range []struct {
		name      string
		failAt    int
		wrongSize bool
	}{{"first", 1, false}, {"second", 2, false}, {"size", 1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			result, _, err := DecryptALACFragment(context.Background(), data, init, func(_ context.Context, s []byte) ([]byte, error) {
				calls++
				if calls == tc.failAt {
					if tc.wrongSize {
						return s[:1], nil
					}
					return s, errors.New("test failure")
				}
				return s, nil
			})
			if err == nil || result != nil || !bytes.Equal(data, original) {
				t.Fatal("partial output escaped")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, _, err := DecryptALACFragment(ctx, data, init, func(context.Context, []byte) ([]byte, error) { t.Fatal("called on cancellation"); return nil, nil }); err == nil || p != nil {
		t.Fatal("cancellation ignored")
	}
}

func TestALACMalformedRangesAndAuxiliary(t *testing.T) {
	init, err := ParseALACInitialization(alacTestInit())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, box string
		offset    int
		value     uint32
	}{
		{"negative data offset", "trun", 8, 0xffffffff}, {"outside mdat", "trun", 8, 0}, {"zero size", "trun", 12, 0}, {"oversized sample", "trun", 16, 1 << 30}, {"extra sample", "trun", 4, 3},
		{"invalid description", "tfhd", 8, 3}, {"wrong track", "tfhd", 4, 2}, {"zero duration", "tfhd", 12, 0},
		{"senc count", "senc", 4, 3}, {"senc clear prefix", "senc", 8, 0x10001}, {"senc size", "senc", 12, 20},
		{"saiz count", "saiz", 5, 3}, {"saio offset", "saio", 8, 0}, {"saio version", "saio", 0, 0x02000000},
		{"decode time overflow", "tfdt", 4, 0xffffffff},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := alacTestFragment()
			b, _ := alacPath(data, "moof", "traf", tc.box)
			binary.BigEndian.PutUint32(data[b.payload+tc.offset:], tc.value)
			if tc.name == "decode time overflow" {
				binary.BigEndian.PutUint32(data[b.payload+8:], 0xffffffff)
			}
			if _, err := ParseALACFragment(data, init); err == nil {
				t.Fatal("accepted invalid fragment")
			}
		})
	}
	for n := 0; n < len(alacTestFragment()); n++ {
		if _, err := ParseALACFragment(alacTestFragment()[:n], init); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
}

// Optional local integration fixture; no protected fixture is committed.
func TestALACAcquiredLayout(t *testing.T) {
	dir := os.Getenv("APPLEMUSIC_ALAC_FIXTURE")
	if dir == "" {
		t.Skip("local acquired fixture not configured")
	}
	data, err := os.ReadFile(filepath.Join(dir, "init-0000.bin"))
	if err != nil {
		t.Fatal(err)
	}
	init, err := ParseALACInitialization(data)
	if err != nil {
		t.Fatal("initialization", err)
	}
	names, err := filepath.Glob(filepath.Join(dir, "segment-*.bin"))
	if err != nil || len(names) == 0 {
		t.Fatal("no fragments")
	}
	var end uint64
	samples := 0
	for _, name := range names {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := ParseALACFragment(data, init)
		clear(data)
		if err != nil {
			t.Fatal(filepath.Base(name), err)
		}
		if f.DecodeTime != end {
			t.Fatal("timeline mismatch")
		}
		end += f.Duration
		samples += len(f.Samples)
	}
	t.Logf("validated segments=%d samples=%d sampleRate=%d bitDepth=%d channels=%d", len(names), samples, init.Timescale, init.Configuration.BitDepth, init.Configuration.Channels)
}
