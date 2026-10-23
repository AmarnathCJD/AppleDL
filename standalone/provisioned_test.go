package standalone

import (
	"context"
	"os"
	"testing"

	"github.com/AmarnathCJD/AppleDL"
)

// Explicit local integration: no network, provisioning or secret output. The
// existing Go-encrypted device stays in place and is never recreated.
func TestProvisionedDeviceReopens(t *testing.T) {
	dir := os.Getenv("APPLEMUSIC_PROVISIONED_STATE")
	if dir == "" {
		t.Skip("requires an explicitly supplied provisioned local device")
	}
	var previousID string
	for range 2 {
		func() {
			d, err := Open(context.Background(), Config{StateDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := d.Close(); err != nil {
					t.Error(err)
				}
			}()
			id, err := d.StableID(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if previousID != "" && previousID != id {
				t.Fatal("identity changed on reopen")
			}
			previousID = id
			status, err := d.Status(context.Background(), applemusic.AnisetteV3DSID)
			if err != nil || status != 0 {
				t.Fatalf("saved device unusable: status=%d error=%v", status, err)
			}
			for range 2 {
				h, err := d.IdMSDeviceHeaders(context.Background(), applemusic.SRPInit)
				if err != nil {
					t.Fatal(err)
				}
				if h.Get("X-Apple-I-MD") == "" || h.Get("X-Apple-I-MD-M") == "" {
					t.Fatal("missing device headers")
				}
			}
		}()
	}
	t.Log("preserved device reopened twice and generated headers; values hidden")
}
