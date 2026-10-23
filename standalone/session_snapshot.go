package standalone

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/internal/envelope"
)

// Session snapshots bind the entire provisioning state and both account
// snapshots together in one portable bearer envelope. Passwords are absent.
type sessionSnapshot struct {
	Version  int                    `json:"version"`
	Device   *diskState             `json:"device"`
	Account  *SavedIdMSAccount      `json:"account"`
	Commerce *SavedCommerceResponse `json:"commerce"`
}

func (*sessionSnapshot) String() string   { return "sessionSnapshot{redacted}" }
func (*sessionSnapshot) GoString() string { return "sessionSnapshot{redacted}" }

func (s *sessionSnapshot) destroy() {
	if s.Device != nil {
		for _, b := range s.Device.Files {
			clear(b)
		}
	}
	s.Account.Destroy()
	s.Commerce.Destroy()
	*s = sessionSnapshot{}
}

func validSessionSnapshot(s *sessionSnapshot) bool {
	if s == nil || s.Version != 1 || s.Device == nil || !validDiskState(s.Device) ||
		!validAccount(s.Account, s.Device.AndroidID) || !validCommerceSnapshot(s.Commerce, s.Device.AndroidID) ||
		!strings.EqualFold(s.Account.Username, s.Commerce.Username) {
		return false
	}
	r, err := s.Commerce.Response()
	if err != nil {
		return false
	}
	defer r.Destroy()
	a, err := r.ExtractAccount()
	if err != nil {
		return false
	}
	var alt string
	if json.Unmarshal(s.Account.Exchange.AccountData["adsid"], &alt) != nil || alt == "" || alt != a.AltDSID {
		return false
	}
	session, err := am.NewMediaTokenSession(r, s.Commerce.ObtainedAt)
	if err != nil {
		return false
	}
	session.Destroy()
	return true
}

// ExportSession returns URL-safe Base64 of portable bearer credentials; it is not encrypted.
// A successful export certifies structural consistency, not online token validity.
func (d *Device) ExportSession(ctx context.Context) (encoded string, err error) {
	err = d.run(ctx, false, func() error {
		if err := d.persist(); err != nil {
			return err
		}
		a, err := loadAccount(d.store.dir, d.state.AndroidID)
		if err != nil {
			return err
		}
		defer a.Destroy()
		c, err := loadCommerceSnapshot(d.store.dir, d.state.AndroidID)
		if err != nil {
			return err
		}
		defer c.Destroy()
		s := &sessionSnapshot{Version: 1, Device: d.state, Account: a, Commerce: c}
		if !validSessionSnapshot(s) {
			return errors.New("session identity or credential binding is invalid")
		}
		plain, err := json.Marshal(s)
		if err != nil {
			return errors.New("cannot encode session")
		}
		defer clear(plain)
		if len(plain) > stateLimit-4096 {
			return errors.New("session exceeds size limit")
		}
		raw, err := envelope.Encode("AMSES001", plain, stateLimit)
		if err != nil {
			return err
		}
		defer clear(raw)
		encoded = base64.RawURLEncoding.EncodeToString(raw)
		return nil
	})
	return
}

func decodeSession(encoded string) (*sessionSnapshot, error) {
	invalid := errors.New("invalid session or unsupported version")
	if len(encoded) == 0 || len(encoded) > base64.RawURLEncoding.EncodedLen(stateLimit) {
		return nil, invalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	defer clear(raw)
	if err != nil {
		return nil, invalid
	}
	plain, err := envelope.Decode("AMSES001", raw, stateLimit)
	if err != nil {
		return nil, invalid
	}
	defer clear(plain)
	s := new(sessionSnapshot)
	if json.Unmarshal(plain, s) != nil || !validSessionSnapshot(s) {
		s.destroy()
		return nil, invalid
	}
	return s, nil
}

// RestoreSession installs a validated snapshot into a NEW absolute directory.
// Existing directories are never replaced. Callers can stage this device and
// verify it online before swapping it into a running client.
func RestoreSession(ctx context.Context, cfg Config, encoded string) (*Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := decodeSession(encoded)
	if err != nil {
		return nil, err
	}
	defer s.destroy()
	if !filepath.IsAbs(cfg.StateDir) {
		return nil, errors.New("session directory must be absolute")
	}
	if err := os.Mkdir(cfg.StateDir, 0700); err != nil {
		return nil, errors.New("session requires a new directory")
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(cfg.StateDir)
		}
	}()
	store, state, err := openState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	for _, b := range state.Files {
		clear(b)
	}
	err = store.save(s.Device)
	if err == nil {
		err = saveAccount(cfg.StateDir, s.Account)
	}
	if err == nil {
		err = saveCommerceSnapshot(cfg.StateDir, s.Commerce)
	}
	store.close()
	if err != nil {
		return nil, err
	}
	d, err := Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	ok = true
	return d, nil
}
