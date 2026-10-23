package applemusic

import (
	"encoding/binary"
	"errors"
	"math"
)

// MP4Inspection inventories bounded ISO BMFF structure without returning sample
// payloads, PSSH data, key IDs, IV bytes, or vendor-controlled strings. It is not
// a decoder and does not establish that encrypted samples can be played.
type MP4Inspection struct {
	Boxes              map[string]int         `json:"boxes"`
	UnknownBoxes       int                    `json:"unknownBoxes"`
	MediaPayloadBytes  int64                  `json:"mediaPayloadBytes"`
	FragmentSamples    uint64                 `json:"fragmentSamples"`
	AudioEntries       []MP4AudioEntry        `json:"audioEntries,omitempty"`
	OriginalFormats    []string               `json:"originalFormats,omitempty"`
	ProtectionSchemes  []string               `json:"protectionSchemes,omitempty"`
	TrackEncryption    []MP4TrackEncryption   `json:"trackEncryption,omitempty"`
	ALACConfigurations []MP4ALACConfiguration `json:"alacConfigurations,omitempty"`
}

type MP4ALACConfiguration struct {
	FrameSamples uint32 `json:"frameSamples"`
	BitDepth     byte   `json:"bitDepth"`
	Channels     byte   `json:"channels"`
	SampleRate   uint32 `json:"sampleRate"`
}

type MP4AudioEntry struct {
	Format         string  `json:"format"`
	Version        uint16  `json:"version"`
	Channels       uint16  `json:"channels"`
	SampleSizeBits uint16  `json:"sampleSizeBits"`
	SampleRate     float64 `json:"sampleRate"`
}

type MP4TrackEncryption struct {
	Version         byte `json:"version"`
	Protected       bool `json:"protected"`
	PerSampleIVSize byte `json:"perSampleIVSize"`
	CryptBlocks     byte `json:"cryptBlocks"`
	SkipBlocks      byte `json:"skipBlocks"`
	ConstantIVSize  byte `json:"constantIVSize"`
}

func knownMP4Format(raw string) string {
	switch raw {
	case "mp4a", "alac", "enca", "drms", "ac-3", "ec-3", "ac-4", "Opus", "fLaC":
		return raw
	}
	return "unrecognized"
}

// InspectMP4 accepts one initialization section or complete fragment byte range.
// Parsing is bounded by 32 MiB, 16 levels and 10,000 boxes. Unknown boxes are
// counted and skipped by declared size. Only known container types are descended.
func InspectMP4(data []byte) (*MP4Inspection, error) {
	bad := errors.New("invalid or unsupported MP4 structure")
	if len(data) < 8 || int64(len(data)) > MaxHLSResourceBytes {
		return nil, bad
	}
	out := &MP4Inspection{Boxes: map[string]int{}}
	boxes := 0
	var walk func([]byte, int, string) error
	walk = func(data []byte, depth int, parent string) error {
		if depth > 16 {
			return bad
		}
		for len(data) > 0 {
			if len(data) < 8 {
				return bad
			}
			n := uint64(binary.BigEndian.Uint32(data))
			header := uint64(8)
			kind := string(data[4:8])
			if n == 1 {
				if len(data) < 16 {
					return bad
				}
				n = binary.BigEndian.Uint64(data[8:])
				header = 16
			}
			if n == 0 {
				n = uint64(len(data))
			}
			if n < header || n > uint64(len(data)) {
				return bad
			}
			p := data[header:n]
			data = data[n:]
			boxes++
			if boxes > 10000 {
				return bad
			}
			known := true
			switch kind {
			case "ftyp", "styp", "free", "skip", "wide", "mvhd", "tkhd", "mdhd", "hdlr", "smhd", "vmhd", "dref", "stts", "ctts", "stsc", "stsz", "stco", "co64", "stss", "trex", "mfhd", "tfhd", "tfdt", "sidx", "pssh", "esds", "chan", "btrt", "sbgp", "sgpd", "uuid":
			case "moov", "trak", "mdia", "minf", "stbl", "mvex", "moof", "traf", "sinf", "schi", "dinf":
				if err := walk(p, depth+1, kind); err != nil {
					return err
				}
			case "mdat":
				out.MediaPayloadBytes += int64(len(p))
			case "stsd":
				if len(p) < 8 || p[0] != 0 {
					return bad
				}
				count := binary.BigEndian.Uint32(p[4:])
				entries := p[8:]
				seen := uint32(0)
				for len(entries) > 0 {
					if len(entries) < 8 {
						return bad
					}
					size := binary.BigEndian.Uint32(entries)
					if size < 8 || uint64(size) > uint64(len(entries)) {
						return bad
					}
					seen++
					entries = entries[size:]
				}
				if count != seen {
					return bad
				}
				if err := walk(p[8:], depth+1, kind); err != nil {
					return err
				}
			case "mp4a", "alac", "enca", "drms", "ac-3", "ec-3", "ac-4", "Opus", "fLaC":
				// Codec-configuration children can share the sample entry's fourcc.
				if parent != "stsd" {
					if kind == "alac" {
						if len(p) != 28 || p[0] != 0 {
							return bad
						}
						out.ALACConfigurations = append(out.ALACConfigurations, MP4ALACConfiguration{FrameSamples: binary.BigEndian.Uint32(p[4:]), BitDepth: p[9], Channels: p[13], SampleRate: binary.BigEndian.Uint32(p[24:])})
					}
					break
				}
				if len(p) < 28 {
					return bad
				}
				v := binary.BigEndian.Uint16(p[8:10])
				offset := 28
				switch v {
				case 0:
				case 1:
					offset += 16
				default:
					return bad
				}
				if len(p) < offset {
					return bad
				}
				out.AudioEntries = append(out.AudioEntries, MP4AudioEntry{Format: kind, Version: v, Channels: binary.BigEndian.Uint16(p[16:]), SampleSizeBits: binary.BigEndian.Uint16(p[18:]), SampleRate: float64(binary.BigEndian.Uint32(p[24:])) / 65536})
				if err := walk(p[offset:], depth+1, kind); err != nil {
					return err
				}
			case "frma":
				if len(p) != 4 {
					return bad
				}
				out.OriginalFormats = append(out.OriginalFormats, knownMP4Format(string(p)))
			case "schm":
				if len(p) < 12 || p[0] != 0 {
					return bad
				}
				scheme := string(p[4:8])
				switch scheme {
				case "cenc", "cbcs", "cens", "cbc1", "itun":
				default:
					scheme = "unrecognized"
				}
				out.ProtectionSchemes = append(out.ProtectionSchemes, scheme)
			case "tenc":
				if len(p) < 24 || p[0] > 1 || p[6] > 1 {
					return bad
				}
				e := MP4TrackEncryption{Version: p[0], Protected: p[6] == 1, PerSampleIVSize: p[7]}
				if p[0] == 1 {
					e.CryptBlocks = p[5] >> 4
					e.SkipBlocks = p[5] & 15
				}
				if e.Protected && e.PerSampleIVSize == 0 {
					if len(p) < 25 || int(p[24])+25 != len(p) {
						return bad
					}
					e.ConstantIVSize = p[24]
				} else if len(p) != 24 {
					return bad
				}
				out.TrackEncryption = append(out.TrackEncryption, e)
			case "trun":
				if len(p) < 8 || p[0] > 1 {
					return bad
				}
				flags := binary.BigEndian.Uint32(p[:4]) & 0xffffff
				if flags & ^uint32(0xf05) != 0 {
					return bad
				}
				samples := binary.BigEndian.Uint32(p[4:])
				size := uint64(8)
				fields := uint64(0)
				if flags&1 != 0 {
					size += 4
				}
				if flags&4 != 0 {
					size += 4
				}
				for _, flag := range []uint32{0x100, 0x200, 0x400, 0x800} {
					if flags&flag != 0 {
						fields += 4
					}
				}
				if size+uint64(samples)*fields != uint64(len(p)) || math.MaxUint64-out.FragmentSamples < uint64(samples) {
					return bad
				}
				out.FragmentSamples += uint64(samples)
			case "senc":
				if len(p) < 8 {
					return bad
				}
			case "saiz":
				if len(p) < 9 {
					return bad
				}
			case "saio":
				if len(p) < 8 {
					return bad
				}
			default:
				known = false
				out.UnknownBoxes++
			}
			if known {
				out.Boxes[kind]++
			}
		}
		return nil
	}
	if err := walk(data, 0, ""); err != nil {
		return nil, err
	}
	return out, nil
}
