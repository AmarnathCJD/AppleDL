// Package accountflow composes standalone IdMS and commerce authentication.
package accountflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

// AuthenticateCommerce exchanges a saved PET for commerce credentials. Only the
// explicit SP provisioning challenge is retried, once; passwords are not used.
func AuthenticateCommerce(ctx context.Context, w io.Writer, c *applemusic.Client, d *standalone.Device, cfg standalone.Config, httpClient *http.Client) (err error) {
	account, err := d.LoadIdMSAccount(ctx)
	if err != nil {
		return err
	}
	defer account.Destroy()
	expiry, e := account.Exchange.PETExpiry()
	if e != nil {
		return e
	}
	if !time.Now().Before(expiry) {
		fmt.Fprintln(w, "Saved PET has expired; a fresh account exchange is required.")
		return errors.New("saved PET expired")
	}
	pet, err := account.Exchange.PET()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "Loaded saved PET with matching local device.")
	m, err := d.Metadata(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "Fetching reviewed AndroidMusic commerce profile.")
	profile, err := c.FetchCommerceProfile(ctx, m.UserAgent)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "Preparing local SAP signing session.")
	signer, err := standalone.NewSAPSigner(ctx, cfg, m.StableID)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, signer.Close()) }()
	if err = signer.Setup(ctx, httpClient, applemusic.SAPCertURL, applemusic.SAPSetupURL, m.UserAgent); err != nil {
		return err
	}
	credentials := applemusic.PETCredentials{AppleID: account.Username, PET: pet, GUID: m.DeviceID}
	options := applemusic.CommerceOptions{PrepareRequest: d.CommercePreparer(profile, signer)}
	for attempt := 0; attempt < 2; attempt++ {
		fmt.Fprintf(w, "Sending signed commerce request %d.\n", attempt+1)
		response, authErr := c.AuthenticatePET(ctx, applemusic.CommerceAuthURL, credentials, options)
		defer response.Destroy()
		if response != nil {
			fmt.Fprintf(w, "Commerce HTTP status: %d\n", response.HTTPStatus)
		}
		if response != nil && response.HTTPHeaders.Get("X-Apple-AMD-Action") == "SP" && attempt == 0 {
			var redirect *applemusic.RedirectError
			if errors.As(authErr, &redirect) {
				return authErr
			}
			fmt.Fprintln(w, "Apple requested V1.5 device provisioning (SP).")
			h, err := profile.Headers(m)
			if err != nil {
				return err
			}
			if err = c.ProvisionCommerceAMD(ctx, profile, m.DeviceID, h, response.HTTPHeaders, d.Start); err != nil {
				return err
			}
			fmt.Fprintln(w, "V1.5 provisioning finished; retrying once with fresh device headers.")
			continue
		}
		if authErr != nil {
			return authErr
		}
		if parsed, e := response.ExtractAccount(); e == nil {
			var altDSID string
			if json.Unmarshal(account.Exchange.AccountData["adsid"], &altDSID) != nil || altDSID == "" || parsed.AltDSID != altDSID {
				return errors.New("commerce identity does not match the saved IdMS account")
			}
		}
		if err := d.SaveCommerceResponse(ctx, account.Username, response); err != nil {
			return err
		}
		fmt.Fprintln(w, "Commerce response and cookies saved with Go AES-GCM and local device binding.")
		if response.Observation() != applemusic.CommerceCredentialReceived {
			fmt.Fprintln(w, "Saved commerce response remains unclassified.")
			return errors.New("commerce response requires account-flow classification")
		}
		fmt.Fprintln(w, "Commerce credential received. Media API access has not been verified; plist status remains uninterpreted.")
		return nil
	}
	return errors.New("commerce challenge remains unresolved")
}
