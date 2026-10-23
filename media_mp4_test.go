package applemusic

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func mp4Box(kind string, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(out)))
	copy(out[4:], kind)
	copy(out[8:], body)
	return out
}

func TestInspectProtectedALACMetadata(t *testing.T) {
	tenc := make([]byte, 24)
	tenc[0] = 1
	tenc[5] = 0x19
	tenc[6] = 1
	tenc[7] = 16
	copy(tenc[8:], "private-key-id!!")
	schm := make([]byte, 12)
	copy(schm[4:], "cbcs")
	header := make([]byte, 28)
	binary.BigEndian.PutUint16(header[6:], 1)
	binary.BigEndian.PutUint16(header[16:], 2)
	binary.BigEndian.PutUint16(header[18:], 16)
	binary.BigEndian.PutUint32(header[24:], 44100<<16)
	config := make([]byte, 28)
	binary.BigEndian.PutUint32(config[4:], 4096)
	config[9] = 24
	config[13] = 2
	binary.BigEndian.PutUint32(config[24:], 48000)
	entry := mp4Box("enca", header, mp4Box("alac", config), mp4Box("sinf", mp4Box("frma", []byte("alac")), mp4Box("schm", schm), mp4Box("schi", mp4Box("tenc", tenc))))
	stsd := mp4Box("stsd", []byte{0, 0, 0, 0, 0, 0, 0, 1}, entry)
	got, err := InspectMP4(mp4Box("moov", mp4Box("trak", mp4Box("mdia", mp4Box("minf", mp4Box("stbl", stsd))))))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ALACConfigurations) != 1 || got.ALACConfigurations[0].BitDepth != 24 || got.ALACConfigurations[0].SampleRate != 48000 || got.OriginalFormats[0] != "alac" || got.ProtectionSchemes[0] != "cbcs" || got.AudioEntries[0].Format != "enca" || got.AudioEntries[0].SampleRate != 44100 {
		t.Fatal("codec metadata mismatch")
	}
	if e := got.TrackEncryption[0]; !e.Protected || e.PerSampleIVSize != 16 || e.CryptBlocks != 1 || e.SkipBlocks != 9 {
		t.Fatal("protection metadata mismatch")
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "private") {
		t.Fatal("key identifier leaked")
	}
}

func TestInspectMP4FragmentAndMalformedInput(t *testing.T) {
	trun := make([]byte, 8+4+3*8)
	trun[2] = 3
	trun[3] = 1
	binary.BigEndian.PutUint32(trun[4:], 3)
	good := append(mp4Box("moof", mp4Box("traf", mp4Box("trun", trun))), mp4Box("mdat", []byte("encrypted-private-payload"))...)
	got, err := InspectMP4(good)
	if err != nil || got.FragmentSamples != 3 || got.MediaPayloadBytes != 25 {
		t.Fatal("fragment mismatch", err, got)
	}
	cases := [][]byte{nil, {0, 0, 0, 7, 'f', 'r', 'e', 'e'}, {0, 0, 0, 1, 'f', 'r', 'e', 'e'}, mp4Box("moov", []byte{1}), mp4Box("stsd", []byte{0, 0, 0, 0, 0, 0, 0, 1}), mp4Box("trun", trun[:len(trun)-1]), mp4Box("tenc", make([]byte, 2))}
	deep := mp4Box("free")
	for i := 0; i < 18; i++ {
		deep = mp4Box("moov", deep)
	}
	cases = append(cases, deep, bytes.Repeat(mp4Box("free"), 10001))
	for i, b := range cases {
		if _, e := InspectMP4(b); e == nil {
			t.Fatalf("accepted malformed case %d", i)
		}
	}
	unknown := mp4Box("X123", []byte("private"))
	got, err = InspectMP4(unknown)
	if err != nil || got.UnknownBoxes != 1 || len(got.Boxes) != 0 {
		t.Fatal("unknown box mishandled")
	}
}
