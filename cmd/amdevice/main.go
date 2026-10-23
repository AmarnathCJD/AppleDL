// amdevice provisions and checks a separate standalone device. It never prints
// identifiers, request/response bodies, native provisioning material or OTPs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

func run() (err error) {
	cfg := standalone.Config{}

	flag.StringVar(&cfg.StateDir, "state", filepath.Join(".applemusic", "device"), "AES-GCM encrypted local device directory")
	provision := flag.Bool("provision", false, "Provision only if local V3 status is unprovisioned")
	otp := flag.Bool("otp", false, "Verify fresh V3 authentication headers; hide all values")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	cfg.StateDir, err = filepath.Abs(cfg.StateDir)
	if err != nil {
		return errors.New("invalid state path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d, err := standalone.Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, d.Close()) }()
	status, err := d.Status(ctx, applemusic.AnisetteV3DSID)
	if err != nil {
		return err
	}
	fmt.Printf("Standalone V3 status: %d\n", status)
	if *provision && status != 0 {
		if status != -45061 {
			return errors.New("refusing provisioning: unexpected existing native state")
		}
		c, err := applemusic.New(applemusic.Config{})
		if err != nil {
			return err
		}
		err = c.ProvisionDevice(ctx, applemusic.ProvisioningOptions{
			// Production endpoints from the supplied app's IdMS lookup bag.
			StartURL:  "https://gsd.apple.com/grandslam/MidService/startMachineProvisioning",
			FinishURL: "https://gsd.apple.com/grandslam/MidService/finishMachineProvisioning",
			DSID:      applemusic.AnisetteV3DSID, Headers: d.ProvisioningHeaders, Native: d.Start,
		})
		if err != nil {
			return err
		}
		status, err = d.Status(ctx, applemusic.AnisetteV3DSID)
		if err != nil {
			return err
		}
		fmt.Printf("Standalone V3 status after provisioning: %d\n", status)
		if status != 0 {
			return errors.New("provisioning did not establish usable native state")
		}
	}
	if *otp {
		var previous string
		for i := 1; i <= 2; i++ {
			if i > 1 {
				timer := time.NewTimer(1100 * time.Millisecond)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				}
			}
			h, err := d.IdMSDeviceHeaders(ctx, applemusic.SRPInit)
			if err != nil {
				return err
			}
			value := h.Get("X-Apple-I-MD")
			if value == "" {
				return errors.New("native provider did not produce an OTP")
			}
			if previous != "" {
				fmt.Printf("OTP changed across requests: %t\n", value != previous)
			}
			previous = value
			fmt.Printf("Fresh V3 headers %d: succeeded (%d headers; values hidden)\n", i, len(h))
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var provisioning *applemusic.ProvisioningError
		if errors.As(err, &provisioning) {
			// All providers in this command use fixed redacted errors.
			fmt.Fprintln(os.Stderr, provisioning.Err)
		}
		var native *standalone.StatusError
		if errors.As(err, &native) {
			fmt.Fprintf(os.Stderr, "Native status: %d\n", native.Code)
		}
		var httpErr *applemusic.HTTPError
		if errors.As(err, &httpErr) {
			fmt.Fprintf(os.Stderr, "HTTP status: %d\n", httpErr.StatusCode)
		}
		os.Exit(1)
	}
}
