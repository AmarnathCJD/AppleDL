package standalone

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

// Reproduces the missing-serial failure using the pinned native runtime,
// public certificate and synthetic content URI. No account state, HTTP
// requests or Android process are involved.
func TestPlaybackSerialRegression(t *testing.T) {
	if os.Getenv("APPLEMUSIC_PLAYBACK_PROBE") != "1" {
		t.Skip("playback native integration requires explicit opt-in")
	}
	f, err := os.Open(os.Getenv("APPLEMUSIC_PLAYBACK_CERTIFICATE"))
	if err != nil {
		t.Fatal("public playback certificate unavailable")
	}
	cert, err := io.ReadAll(io.LimitReader(f, bufferLimit+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || len(cert) == 0 || len(cert) > bufferLimit {
		t.Fatal("invalid public playback certificate size")
	}
	defer clear(cert)
	for _, missing := range []bool{true, false} {
		name := "local_serial"
		if missing {
			name = "missing_serial"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			p, err := NewPlaybackExchange(ctx, Config{}, "0123456789abcdef")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := p.Close(); err != nil {
					t.Error(err)
				}
			})
			if missing {
				clear(p.vm.systemProperties)
			}
			spc, err := p.SPC(ctx, cert, "skd://offline-probe", 1)
			defer clear(spc)
			if missing {
				var status *StatusError
				if !errors.As(err, &status) || status.Operation != "sWBoEyhXQd6FTiLw" || status.Code != -42676 || len(spc) != 0 || p.exchange != 0 {
					t.Fatalf("missing serial did not reproduce expected SPC failure: %v", err)
				}
				t.Log("empty_serial_status=-42676 spc_bytes=0")
			} else {
				if err != nil || len(spc) == 0 || p.exchange == 0 {
					t.Fatalf("configured serial SPC failed: %v", err)
				}
				t.Logf("local_serial_status=0 spc_bytes=%d validated_exchange=true", len(spc))
			}
			if again, err := p.SPC(ctx, cert, "skd://offline-probe", 1); err == nil || len(again) != 0 {
				clear(again)
				t.Fatal("SPC attempted twice")
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			if again, err := p.SPC(ctx, cert, "skd://offline-probe", 1); err == nil || len(again) != 0 {
				clear(again)
				t.Fatal("SPC attempted after close")
			}
		})
	}
}
