// amdecrypt replays a private matching ALAC context bundle entirely offline.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/AmarnathCJD/AppleDL/internal/playback"
)

func main() {
	input := flag.String("input", "", "encrypted ALAC file")
	bundle := flag.String("context", "", "matching private license-context.amctx file")
	output := flag.String("output", "", "new output M4A file")
	workers := flag.Int("workers", 0, "workers: 0 automatic, 1..64 explicit")
	flag.Parse()
	if flag.NArg() != 0 || *input == "" || *bundle == "" || *output == "" {
		flag.Usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	r, err := playback.DecryptBundle(ctx, *input, *bundle, *output, *workers, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Offline decryption failed:", err)
		os.Exit(1)
	}
	fmt.Printf("Offline decryption complete: samples=%d samplePass=%s total=%s\n", r.Samples, r.SampleDuration, r.TotalDuration)
}
