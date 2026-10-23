package music

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/internal/accountflow"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

func (c *Client) connectSaved(ctx context.Context, d *standalone.Device, username string) (_ *clientState, err error) {
	saved, err := d.LoadCommerceResponse(ctx)
	if err != nil {
		return nil, err
	}
	defer saved.Destroy()
	if !sameAccount(username, saved.Username) {
		return nil, ErrAccountMismatch
	}
	idms, err := d.LoadIdMSAccount(ctx)
	if err != nil {
		return nil, err
	}
	defer idms.Destroy()
	if !sameAccount(idms.Username, saved.Username) {
		return nil, ErrAccountMismatch
	}
	r, err := saved.Response()
	if err != nil {
		return nil, err
	}
	defer r.Destroy()
	a, err := r.ExtractAccount()
	if err != nil {
		return nil, err
	}
	var alt string
	if json.Unmarshal(idms.Exchange.AccountData["adsid"], &alt) != nil || alt == "" || alt != a.AltDSID {
		return nil, ErrAccountMismatch
	}
	session, err := am.NewMediaTokenSession(r, saved.ObtainedAt)
	if err != nil {
		return nil, err
	}
	defer session.Destroy()
	m, err := d.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	profile, err := c.protocol.FetchMediaTokenProfile(ctx, m.UserAgent)
	if err != nil {
		return nil, err
	}
	signer, err := standalone.NewSAPSigner(ctx, c.runtimeConfig(c.cfg.StateDir), m.StableID)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, signer.Close()) }()
	if err := signer.Setup(ctx, c.cfg.HTTPClient, am.SAPCertURL, am.SAPSetupURL, m.UserAgent); err != nil {
		return nil, err
	}
	token, err := c.protocol.FetchMediaToken(ctx, profile, session, m, d.MediaTokenPreparer(signer))
	if err != nil {
		return nil, err
	}
	defer token.Destroy()
	media, err := am.NewMedia(am.MediaConfig{HTTPClient: c.cfg.HTTPClient, BearerToken: token.Token, DSID: strconv.FormatUint(a.DSID, 10), UserAgent: m.UserAgent, Storefront: c.cfg.Country})
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(c.cfg.Progress, "Saved commerce session accepted; fresh media token received without password exchange.")
	return &clientState{device: d, media: media, username: saved.Username}, nil
}

func (c *Client) login(ctx context.Context, username, password string) (err error) {
	if username == "" || password == "" {
		return ErrSessionRequired
	}
	d, err := standalone.Open(ctx, c.runtimeConfig(c.cfg.StateDir))
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			err = errors.Join(err, d.Close())
		}
	}()
	status, err := d.Status(ctx, am.AnisetteV3DSID)
	if err != nil {
		return err
	}
	if status != 0 {
		if status != -45061 {
			return errors.New("unexpected existing provisioning state")
		}
		err = c.protocol.ProvisionDevice(ctx, am.ProvisioningOptions{
			StartURL:  "https://gsd.apple.com/grandslam/MidService/startMachineProvisioning",
			FinishURL: "https://gsd.apple.com/grandslam/MidService/finishMachineProvisioning",
			DSID:      am.AnisetteV3DSID, Headers: d.ProvisioningHeaders, Native: d.Start,
		})
		if err != nil {
			return err
		}
		status, err = d.Status(ctx, am.AnisetteV3DSID)
		if err != nil {
			return err
		}
		if status != 0 {
			return errors.New("device provisioning did not complete")
		}
	}
	usePET := false
	if _, err := os.Stat(filepath.Join(c.cfg.StateDir, "idms.state")); err == nil {
		saved, err := d.LoadIdMSAccount(ctx)
		if err != nil {
			return err
		}
		if !sameAccount(username, saved.Username) {
			saved.Destroy()
			return ErrAccountMismatch
		}
		expiry, e := saved.Exchange.PETExpiry()
		usePET = e == nil && time.Now().Before(expiry)
		saved.Destroy()
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect saved IdMS state")
	}
	if !usePET {
		fmt.Fprintln(c.cfg.Progress, "Starting one standalone password exchange.")
		result, err := c.protocol.ExchangePassword(ctx, username, password, am.PasswordExchangeOptions{Locale: "en_US", DeviceHeaders: d.IdMSDeviceHeaders})
		if err != nil {
			return err
		}
		err = d.SaveIdMSAccount(ctx, username, result)
		result.Destroy()
		if err != nil {
			return err
		}
	}
	if err := accountflow.AuthenticateCommerce(ctx, c.cfg.Progress, c.protocol, d, c.runtimeConfig(c.cfg.StateDir), c.cfg.HTTPClient); err != nil {
		return err
	}
	s, err := c.connectSaved(ctx, d, username)
	if err != nil {
		return err
	}
	c.state = s
	if err = c.saveSession(c.cfg.SessionFile); err != nil {
		c.state = nil
		return err
	}
	keep = true
	return nil
}
