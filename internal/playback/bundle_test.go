package playback

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AmarnathCJD/AppleDL/internal/envelope"
)

func syntheticBundle() contextBundle {
	h := sha256.Sum256([]byte("fixture"))
	s := hex.EncodeToString(h[:])
	return contextBundle{Layout: bundleLayout{Version: 1, Size: 14, SHA256: s,
		Parts: []bundlePart{{Size: 7, SHA256: s, Context: -1}, {Size: 7, SHA256: s, Context: 0}}}, Contexts: [][]byte{[]byte("synthetic context")}}
}

func TestBundleRejectsInconsistentLayout(t *testing.T) {
	tests := map[string]func(*contextBundle){
		"version":                  func(b *contextBundle) { b.Layout.Version++ },
		"total size":               func(b *contextBundle) { b.Layout.Size++ },
		"negative size":            func(b *contextBundle) { b.Layout.Parts[1].Size = -1 },
		"initialization context":   func(b *contextBundle) { b.Layout.Parts[0].Context = 0 },
		"missing segment context":  func(b *contextBundle) { b.Layout.Parts[1].Context = 1 },
		"negative segment context": func(b *contextBundle) { b.Layout.Parts[1].Context = -1 },
		"unused context":           func(b *contextBundle) { b.Contexts = append(b.Contexts, []byte("unused")) },
		"empty context":            func(b *contextBundle) { b.Contexts[0] = nil },
		"malformed hash":           func(b *contextBundle) { b.Layout.Parts[1].SHA256 = "invalid" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			b := syntheticBundle()
			if !validBundle(&b) {
				t.Fatal("fixture layout invalid")
			}
			mutate(&b)
			if validBundle(&b) {
				t.Fatal("inconsistent layout accepted")
			}
		})
	}
}

func TestContextBindingIncludesLayoutAndOrdinal(t *testing.T) {
	b := syntheticBundle()
	before := contextBinding(b.Layout, 0)
	if before == contextBinding(b.Layout, 1) {
		t.Fatal("ordinal is not bound")
	}
	b.Layout.Parts[1].Context++
	if before == contextBinding(b.Layout, 0) {
		t.Fatal("segment association is not bound")
	}
}

func TestBundleReplayRejectsCorruptionBeforeCreatingOutput(t *testing.T) {
	for _, mode := range []string{"damaged envelope", "truncated ciphertext", "changed ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			input, bundle, output := filepath.Join(dir, "input"), filepath.Join(dir, "context"), filepath.Join(dir, "output")
			b := syntheticBundle()
			plain, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := envelope.Encode("AMBND001", plain, bundleLimit)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("fixturefixture")
			switch mode {
			case "damaged envelope":
				raw[len(raw)-1] ^= 1
			case "truncated ciphertext":
				data = data[:len(data)-1]
			case "changed ciphertext":
				data[0] ^= 1
			}
			if err := os.WriteFile(input, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(bundle, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := DecryptBundle(context.Background(), input, bundle, output, 1, nil); err == nil {
				t.Fatal("corrupt input accepted")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("rejection left an output")
			}
		})
	}
}

func TestBundleReplayPreservesExistingOutputAndCancellation(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	before := []byte("existing output")
	if err := os.WriteFile(output, before, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptBundle(context.Background(), "missing", "missing", output, 1, nil); err == nil {
		t.Fatal("existing output accepted")
	}
	after, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing output changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecryptBundle(ctx, "missing", "missing", output, 1, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}
