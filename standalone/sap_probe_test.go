package standalone

import (
	"context"
	"os"
	"testing"
	"time"
)

// Uses an isolated identity; never reads saved device or account state.
func TestSAPNativeProbe(t *testing.T) {
	if os.Getenv("APPLEMUSIC_SAP_PROBE") != "1" {
		t.Skip("SAP integration requires explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := NewSAPSigner(ctx, Config{}, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Sign(ctx, []byte("test")); err == nil {
		t.Fatal("signed before setup")
	}
	if os.Getenv("APPLEMUSIC_SAP_ONLINE") == "1" {
		err = s.Setup(ctx, nil, "https://s.mzstatic.com/sap/setupCert.plist", "https://fpinit.itunes.apple.com/v1/signSapSetup", "Music/7.0.0 Android/15 model/GooglePixel9 build/1606 (dt:66) AMS/1")
		if err != nil {
			t.Fatal(err)
		}
		for _, body := range []string{"standalone-signature-probe", "second-different-request"} {
			signature, err := s.Sign(ctx, []byte(body))
			if err != nil || len(signature) == 0 {
				t.Fatalf("sign failed: %v", err)
			}
			t.Logf("Production SAP signature bytes=%d", len(signature))
			clear(signature)
		}
		if err := s.Setup(ctx, nil, "https://s.mzstatic.com/sap/setupCert.plist", "https://fpinit.itunes.apple.com/v1/signSapSetup", "test"); err == nil {
			t.Fatal("repeated setup allowed")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(ctx, []byte("test")); err == nil {
		t.Fatal("signed after close")
	}
}
