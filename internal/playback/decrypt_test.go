package playback

import (
	"reflect"
	"testing"

	am "github.com/AmarnathCJD/AppleDL"
)

func alacKeyFixture() *am.HLSManifest {
	mapIndex := 0
	key := func(uri, version string) am.HLSKey {
		return am.HLSKey{Method: "SAMPLE-AES", Format: "com.apple.streamingkeydelivery", URI: uri, Versions: version}
	}
	return &am.HLSManifest{
		Keys: []am.HLSKey{
			{Method: "unsupported-unused"},
			key("skd://fixture-a", ""),
			key("skd://fixture-b", "1"),
			key("skd://fixture-a", "1"),
			key("skd://fixture-a", "2"),
		},
		Maps: []am.HLSMap{{KeyIndices: []int{1}}},
		Segments: []am.HLSSegment{
			{MapIndex: &mapIndex, KeyIndices: []int{3}},
			{MapIndex: &mapIndex, KeyIndices: []int{2}},
			{MapIndex: &mapIndex, KeyIndices: []int{4}},
			{MapIndex: &mapIndex, KeyIndices: []int{1}},
		},
	}
}

func TestALACSegmentLicenseAssociation(t *testing.T) {
	m := alacKeyFixture()
	keys, err := alacPlaybackKeys(m)
	if err != nil || len(keys) != 3 {
		t.Fatal("referenced keys were not deduplicated", err)
	}
	got, err := alacSegmentKeys(m, keys)
	if err != nil || !reflect.DeepEqual(got, []int{0, 1, 2, 0}) {
		t.Fatal("segment rotation or version association failed", err)
	}
	// A context's ordinal is independent of its original playlist key index.
	keys[0], keys[2] = keys[2], keys[0]
	got, err = alacSegmentKeys(m, keys)
	if err != nil || !reflect.DeepEqual(got, []int{2, 1, 0, 2}) {
		t.Fatal("segment selected the wrong license after reordering", err)
	}
	if m.Keys[1].Versions != "" {
		t.Fatal("key normalization mutated the playlist")
	}
	if _, err := alacSegmentKeys(m, keys[1:]); err == nil {
		t.Fatal("missing version-specific license accepted")
	}
}

func TestALACRejectsAmbiguousSegmentAssociation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*am.HLSManifest)
	}{
		{"missing-map", func(m *am.HLSManifest) { m.Segments[1].MapIndex = nil }},
		{"invalid-map", func(m *am.HLSManifest) { n := 1; m.Segments[1].MapIndex = &n }},
		{"multiple-maps", func(m *am.HLSManifest) { m.Maps = append(m.Maps, am.HLSMap{}) }},
		{"missing-key", func(m *am.HLSManifest) { m.Segments[1].KeyIndices = nil }},
		{"multiple-keys", func(m *am.HLSManifest) { m.Segments[1].KeyIndices = []int{1, 2} }},
		{"negative-key", func(m *am.HLSManifest) { m.Segments[1].KeyIndices = []int{-1} }},
		{"outside-key", func(m *am.HLSManifest) { m.Segments[1].KeyIndices = []int{len(m.Keys)} }},
		{"discontinuity", func(m *am.HLSManifest) { m.Segments[1].DiscontinuitySequence++ }},
		{"no-segments", func(m *am.HLSManifest) { m.Segments = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := alacKeyFixture()
			keys, err := alacPlaybackKeys(m)
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(m)
			if _, err := alacSegmentKeys(m, keys); err == nil {
				t.Fatal("invalid segment association accepted")
			}
		})
	}
	if _, err := alacSegmentKeys(nil, nil); err == nil {
		t.Fatal("nil playlist accepted")
	}
}

func TestALACPlaybackKeyValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*am.HLSManifest)
	}{
		{"method", func(m *am.HLSManifest) { m.Keys[2].Method = "AES-128" }},
		{"format", func(m *am.HLSManifest) { m.Keys[2].Format = "identity" }},
		{"uri", func(m *am.HLSManifest) { m.Keys[2].URI = "https://invalid.example" }},
		{"session-key", func(m *am.HLSManifest) { m.Keys[2].Session = true }},
		{"version-negotiation", func(m *am.HLSManifest) { m.Keys[2].Versions = "1/2" }},
		{"zero-version", func(m *am.HLSManifest) { m.Keys[2].Versions = "0" }},
		{"version-overflow", func(m *am.HLSManifest) { m.Keys[2].Versions = "4294967296" }},
		{"invalid-init-key", func(m *am.HLSManifest) { m.Maps[0].KeyIndices = []int{-1} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := alacKeyFixture()
			tc.edit(m)
			if _, err := alacPlaybackKeys(m); err == nil {
				t.Fatal("invalid referenced key accepted")
			}
		})
	}
}

func TestALACUsesAppleKeysAlongsideAlternativeDRM(t *testing.T) {
	m := alacKeyFixture()
	for _, format := range []string{"com.microsoft.playready", "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"} {
		i := len(m.Keys)
		m.Keys = append(m.Keys, am.HLSKey{Method: "SAMPLE-AES", Format: format, URI: "data:text/plain;base64,Zml4dHVyZQ==", Versions: "1"})
		m.Maps[0].KeyIndices = append(m.Maps[0].KeyIndices, i)
		for j := range m.Segments {
			m.Segments[j].KeyIndices = append(m.Segments[j].KeyIndices, i)
		}
	}
	keys, err := alacPlaybackKeys(m)
	if err != nil || len(keys) != 3 {
		t.Fatalf("Apple keys with alternative DRM: %v", err)
	}
	got, err := alacSegmentKeys(m, keys)
	if err != nil || !reflect.DeepEqual(got, []int{0, 1, 2, 0}) {
		t.Fatalf("Apple rotation with alternative DRM: %v", err)
	}
	m.Segments[1].KeyIndices = m.Segments[1].KeyIndices[1:]
	if _, err := alacPlaybackKeys(m); err == nil {
		t.Fatal("segment without Apple key accepted")
	}
}
