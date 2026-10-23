package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	am "github.com/AmarnathCJD/AppleDL"
)

func TestSummariesOmitAssetSecrets(t *testing.T) {
	p := &am.SongPage{Next: "SECRET", Data: []am.Song{{ID: "1", Attributes: am.SongAttributes{
		Name: "Song", Previews: []am.Preview{{URL: "SECRET"}}, ExtendedAssetURLs: map[string]string{"enhancedHls": "SECRET"}, AssetTokens: map[string]string{"t": "SECRET"}, Offers: json.RawMessage(`{"secret":"SECRET"}`),
	}}}}
	b, err := json.Marshal(summarizeSongs(p))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET") || !strings.Contains(string(b), "enhancedHls") {
		t.Fatal("asset summary lost fields or exposed secrets")
	}
	if p.Data[0].Attributes.AssetTokens["t"] != "SECRET" {
		t.Fatal("summary mutated original")
	}
	m := &am.HLSManifest{Keys: []am.HLSKey{{URI: "SECRET", Method: "SAMPLE-AES", Format: "com.apple.streamingkeydelivery"}}, Segments: []am.HLSSegment{{URL: "SECRET", Duration: 2}}}
	b, _ = json.Marshal(summarizeHLS(m))
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("HLS summary exposes URI")
	}
}

func TestMediaCLIRequiresSeparateToken(t *testing.T) {
	t.Setenv("APPLEMUSIC_MEDIA_TOKEN", "")
	if err := run(context.Background(), []string{"search", "-term", "test"}, io.Discard); !errors.Is(err, am.ErrMediaTokenRequired) {
		t.Fatal("missing token not surfaced", err)
	}
}
