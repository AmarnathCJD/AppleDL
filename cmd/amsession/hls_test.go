package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	am "github.com/AmarnathCJD/AppleDL"
)

func TestInspectHLSBoundedAndRedacted(t *testing.T) {
	const secret = "private-url-token-or-key"
	root := &am.HLSManifest{
		Variants: []am.HLSVariant{
			{URL: "root", Codecs: "mp4a.40.2," + secret},
			{URL: "a", Codecs: "alac"}, {URL: "a"}, {URL: "b"}, {URL: "c"}, {URL: "d"},
		},
		Renditions:    []am.HLSRendition{{URL: "e", Type: "AUDIO", Name: secret}},
		Keys:          []am.HLSKey{{Method: "SAMPLE-AES", Format: "com.apple.streamingkeydelivery", URI: secret, IV: secret, Session: true}, {Method: secret, Format: secret}},
		UnhandledTags: []string{secret}, EncryptionSignaled: true,
	}
	var calls []string
	var out bytes.Buffer
	err := inspectHLS(context.Background(), &out, "root", func(_ context.Context, u string) (*am.HLSManifest, error) {
		calls = append(calls, u)
		if u == "root" {
			return root, nil
		}
		return &am.HLSManifest{
			Variants: []am.HLSVariant{{URL: "no-recursion"}},
			Segments: []am.HLSSegment{{URL: secret, Duration: 2.5}},
			Maps:     []am.HLSMap{{URL: secret}},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"root", "a", "b", "c"}) {
		t.Fatalf("unexpected fetch sequence: %v", calls)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatal("server-controlled value leaked")
	}
	for _, want := range []string{"codec mp4a.40.2: variantCount=1", "codec alac: variantCount=1", "Unrecognized codec declaration count: 1", "method=SAMPLE-AES format=com.apple.streamingkeydelivery", "method=unrecognized format=unrecognized", "durationSeconds=2.500", "Distinct direct child playlists: 5"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing summary %q", want)
		}
	}
}

func TestInspectHLSStopsOnFetchFailure(t *testing.T) {
	want := errors.New("bounded fetch failed")
	for _, failAt := range []int{1, 2} {
		var out bytes.Buffer
		calls := 0
		err := inspectHLS(context.Background(), &out, "root", func(_ context.Context, _ string) (*am.HLSManifest, error) {
			calls++
			if calls == failAt {
				return nil, want
			}
			return &am.HLSManifest{Variants: []am.HLSVariant{{URL: "a"}, {URL: "b"}}}, nil
		})
		if !errors.Is(err, want) || calls != failAt {
			t.Fatal("failure was retried or suppressed")
		}
	}
}

func TestSelectHLSMediaExplicitAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		index                        int
		mediaRoot, nested, wantError bool
		calls                        int
	}{
		{"first", 1, false, false, false, 2}, {"second", 2, false, false, false, 2},
		{"invalid-zero", 0, false, false, true, 1}, {"out-of-range", 3, false, false, true, 1},
		{"nested", 1, false, true, true, 2}, {"media-root", 0, true, false, false, 1},
		{"media-root-invalid", 1, true, false, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := selectHLSMedia(context.Background(), "root", tc.index, func(_ context.Context, u string) (*am.HLSManifest, error) {
				calls++
				if (u == "root" && !tc.mediaRoot) || (u != "root" && tc.nested) {
					return &am.HLSManifest{Variants: []am.HLSVariant{{URL: "one"}, {URL: "one"}, {URL: "two"}}}, nil
				}
				if !tc.mediaRoot && u != []string{"one", "two"}[tc.index-1] {
					t.Fatal("wrong selected child")
				}
				return &am.HLSManifest{Segments: []am.HLSSegment{{Duration: 1}}}, nil
			})
			if (err != nil) != tc.wantError || calls != tc.calls || (err == nil && got == nil) {
				t.Fatal("selection mismatch", err)
			}
		})
	}
}

func TestSelectALACVariant(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		calls := 0
		_, err := selectHLSCodec(context.Background(), "root", "alac", func(_ context.Context, u string) (*am.HLSManifest, error) {
			calls++
			if u == "root" {
				v := []am.HLSVariant{{URL: "aac", Codecs: "mp4a.40.2"}, {URL: "lossless", Codecs: "alac"}}
				if ambiguous {
					v = append(v, am.HLSVariant{URL: "another", Codecs: "alac"})
				}
				return &am.HLSManifest{Variants: v}, nil
			}
			if u != "lossless" {
				t.Fatal("selected wrong codec")
			}
			return &am.HLSManifest{Segments: []am.HLSSegment{{}}}, nil
		})
		if ambiguous {
			if err == nil || calls != 1 {
				t.Fatal("ambiguous codec selected")
			}
		} else if err != nil || calls != 2 {
			t.Fatal("ALAC selection failed", err)
		}
	}
}
