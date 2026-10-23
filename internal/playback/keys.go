package playback

import (
	"errors"
	"strconv"
	"strings"

	am "github.com/AmarnathCJD/AppleDL"
)

// Only referenced Apple key declarations are used. Keep the original URI
// untouched. Playlists may advertise alternative DRM systems alongside Apple;
// those declarations are ignored, while each segment must have one Apple key.
func alacPlaybackKeys(m *am.HLSManifest) ([]am.HLSKey, error) {
	if m == nil || len(m.Segments) == 0 {
		return nil, errors.New("ALAC media playlist required")
	}
	indices := make(map[int]bool)
	for _, segment := range m.Segments {
		for _, i := range segment.KeyIndices {
			indices[i] = true
		}
		if segment.MapIndex != nil {
			if *segment.MapIndex < 0 || *segment.MapIndex >= len(m.Maps) {
				return nil, errors.New("invalid ALAC init index")
			}
			for _, i := range m.Maps[*segment.MapIndex].KeyIndices {
				indices[i] = true
			}
		}
	}
	for i := range indices {
		if i < 0 || i >= len(m.Keys) {
			return nil, errors.New("invalid ALAC key index")
		}
	}
	seen := make(map[[2]string]bool)
	var keys []am.HLSKey
	for i, key := range m.Keys {
		if !indices[i] {
			continue
		}
		if key.Format != "com.apple.streamingkeydelivery" {
			continue
		}
		if key.Method != "SAMPLE-AES" || key.Format != "com.apple.streamingkeydelivery" || key.Session || !strings.HasPrefix(key.URI, "skd://") {
			return nil, errors.New("unsupported ALAC key declaration")
		}
		if key.Versions == "" {
			key.Versions = "1"
		}
		version, err := strconv.ParseUint(key.Versions, 10, 32)
		if err != nil || version == 0 {
			return nil, errors.New("ALAC key requires unsupported version negotiation")
		}
		identity := [2]string{key.URI, key.Versions}
		if !seen[identity] {
			keys = append(keys, key)
			seen[identity] = true
		}
	}
	if len(keys) == 0 || len(keys) > 16 {
		return nil, errors.New("ALAC key count outside diagnostic bounds")
	}
	for _, segment := range m.Segments {
		if _, err := appleSegmentKey(m, segment); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

func appleSegmentKey(m *am.HLSManifest, segment am.HLSSegment) (am.HLSKey, error) {
	selected := -1
	for _, i := range segment.KeyIndices {
		if i < 0 || i >= len(m.Keys) {
			return am.HLSKey{}, errors.New("invalid ALAC key association")
		}
		if m.Keys[i].Format != "com.apple.streamingkeydelivery" {
			continue
		}
		if selected >= 0 {
			return am.HLSKey{}, errors.New("ambiguous Apple ALAC key association")
		}
		selected = i
	}
	if selected < 0 {
		return am.HLSKey{}, errors.New("ALAC segment has no Apple key declaration")
	}
	return m.Keys[selected], nil
}

// Keys returns supported key declarations referenced by the selected playlist.
func Keys(m *am.HLSManifest) ([]am.HLSKey, error) { return alacPlaybackKeys(m) }
