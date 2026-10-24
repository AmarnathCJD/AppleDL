package standalone

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"testing"
	"time"
)

func TestLicenseTiming(t *testing.T) {
	if os.Getenv("APPLE_LICENSE_TIMING") != "1" {
		t.Skip("offline timing only")
	}
	cert, err := os.ReadFile("../internal/playback/certificate.bin")
	if err != nil {
		t.Fatal(err)
	}
	for iteration := range 3 {
		start := time.Now()
		p, err := NewPlaybackExchange(t.Context(), Config{}, "0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		setup := time.Since(start)
		v := p.vm
		originalImport := v.goMachine.Import
		rng := rand.New(rand.NewPCG(71, 93))
		// Deterministic entropy/time is confined to this offline test.
		v.goMachine.Import = func(address uint64) {
			switch v.stubs[address] {
			case "arc4random":
				v.setReg(regX0, uint64(rng.Uint32()))
				v.setReg(regPC, v.reg(regLR))
			case "gettimeofday":
				raw := binary.LittleEndian.AppendUint64(nil, 1792800000)
				raw = binary.LittleEndian.AppendUint64(raw, 123456)
				v.write(v.reg(regX0), raw)
				if addr := v.reg(regX0 + 1); addr != 0 {
					v.write(addr, make([]byte, 8))
				}
				v.setReg(regX0, 0)
				v.setReg(regPC, v.reg(regLR))
			default:
				originalImport(address)
			}
		}
		steps := v.goMachine.Steps
		start = time.Now()
		spc, err := p.SPC(t.Context(), cert, "skd://offline-probe", 1)
		duration := time.Since(start)
		if err != nil {
			p.Close()
			t.Fatal(err)
		}
		t.Logf("iteration=%d setup=%s SPC=%s operations=%d bytes=%d digest=%x", iteration, setup, duration, v.goMachine.Steps-steps, len(spc), sha256.Sum256(spc))
		if len(spc) != 5280 || fmt.Sprintf("%x", sha256.Sum256(spc)) != "bc011c3a0435af8628f5d7a5d73699f3c1695524f7ec641c96e0afed1cdfdec9" {
			clear(spc)
			p.Close()
			t.Fatal("deterministic license request differs from reference")
		}
		clear(spc)
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLicenseBlocksAtRuntime(t *testing.T) {
	if os.Getenv("APPLE_LICENSE_VERIFY") != "1" {
		t.Skip("offline verification overlay only")
	}
	cert, err := os.ReadFile("../internal/playback/certificate.bin")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPlaybackExchange(t.Context(), Config{}, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	verifier, ok := any(p.vm.goMachine).(interface{ VerifyLicenseBlock() error })
	if !ok {
		t.Fatal("verification overlay missing")
	}
	seen := map[uint64]int{}
	p.vm.goMachine.Hook = func(pc uint64) {
		switch pc {
		case 0x4064c2f8, 0x406a0630, 0x4067f5c0:
			if seen[pc] >= 2 {
				return
			}
			if err := verifier.VerifyLicenseBlock(); err != nil {
				t.Fatal(err)
			}
			seen[pc]++
			t.Logf("verified every chunk, all registers and mapped memory: entry=%#x sample=%d", pc, seen[pc])
		}
	}
	spc, err := p.SPC(t.Context(), cert, "skd://offline-probe", 1)
	clear(spc)
	p.vm.goMachine.Hook = nil
	if err != nil {
		t.Fatal(err)
	}
	for _, pc := range []uint64{0x4064c2f8, 0x406a0630, 0x4067f5c0} {
		if seen[pc] != 2 {
			t.Fatalf("missing runtime coverage: %#x", pc)
		}
	}
}

func TestLicenseInstructionProfile(t *testing.T) {
	if os.Getenv("APPLE_LICENSE_PROFILE") != "1" {
		t.Skip("offline profiling only")
	}
	cert, err := os.ReadFile("../internal/playback/certificate.bin")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPlaybackExchange(t.Context(), Config{}, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	counts := map[uint64]int{}
	exact := map[uint64]int{}
	edges := map[[2]uint64]int{}
	var prev uint64
	var steps uint64
	p.vm.goMachine.Hook = func(pc uint64) {
		steps++
		if steps%1021 == 0 {
			counts[pc&^4095]++
			exact[pc]++
		}
		if pc >= 0x401e2b00 && pc < 0x401e3600 && pc != prev+4 {
			edges[[2]uint64{prev, pc}]++
		}
		prev = pc
	}
	start := time.Now()
	spc, err := p.SPC(t.Context(), cert, "skd://offline-probe", 1)
	clear(spc)
	if err != nil {
		t.Fatal(err)
	}
	p.vm.goMachine.Hook = nil
	var pages []uint64
	for pc := range counts {
		pages = append(pages, pc)
	}
	sort.Slice(pages, func(i, j int) bool { return counts[pages[i]] > counts[pages[j]] })
	t.Logf("SPC duration=%s operations=%d", time.Since(start), steps)
	for _, pc := range pages[:min(40, len(pages))] {
		t.Logf("page=%#x samples=%d", pc, counts[pc])
	}
	pages = nil
	for pc := range exact {
		pages = append(pages, pc)
	}
	sort.Slice(pages, func(i, j int) bool { return exact[pages[i]] > exact[pages[j]] })
	for _, pc := range pages[:min(60, len(pages))] {
		t.Logf("pc=%#x samples=%d", pc, exact[pc])
	}
	var keys [][2]uint64
	for k := range edges {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return edges[keys[i]] > edges[keys[j]] })
	for _, k := range keys {
		t.Logf("edge=%#x -> %#x count=%d", k[0], k[1], edges[k])
	}
}
