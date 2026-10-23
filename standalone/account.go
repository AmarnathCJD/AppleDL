package standalone

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/internal/securefile"
)

// SavedIdMSAccount is a local snapshot of a verified SRP exchange. It preserves
// status/challenge fields, but does not assert challenge completion, current
// token validity, subscription entitlement or an authenticated media session.
// JSON serialization contains secrets; ordinary formatting is redacted.
type SavedIdMSAccount struct {
	Version    int                           `json:"version"`
	DeviceID   string                        `json:"device_id"`
	Username   string                        `json:"username"`
	ObtainedAt time.Time                     `json:"obtained_at"`
	Exchange   *applemusic.SRPExchangeResult `json:"exchange"`
}

func (*SavedIdMSAccount) String() string   { return "SavedIdMSAccount{redacted}" }
func (*SavedIdMSAccount) GoString() string { return "SavedIdMSAccount{redacted}" }

func (a *SavedIdMSAccount) Destroy() {
	if a != nil {
		a.Exchange.Destroy()
		*a = SavedIdMSAccount{}
	}
}

func validAccount(a *SavedIdMSAccount, deviceID string) bool {
	return a != nil && a.Version == 1 && a.DeviceID == deviceID && deviceID != "" &&
		a.Username != "" && len(a.Username) <= 4096 && !a.ObtainedAt.IsZero() &&
		a.Exchange != nil && len(a.Exchange.AccountData) != 0 &&
		len(a.Exchange.Response["Status"]) != 0 && len(a.Exchange.Response["M2"]) != 0 &&
		len(a.Exchange.Response["spd"]) != 0
}

// SaveIdMSAccount stores only AES-GCM ciphertext alongside the device state.
// Pass a result returned by ExchangePassword or ExchangeContinuationKey: this
// storage layer cannot independently reverify the SRP proof. Existing state is
// replaced using a synchronized temporary file, under the device lock. It never persists the password.
func (d *Device) SaveIdMSAccount(ctx context.Context, username string, result *applemusic.SRPExchangeResult) error {
	return d.run(ctx, false, func() error {
		return saveAccount(d.store.dir, &SavedIdMSAccount{
			Version: 1, DeviceID: d.state.AndroidID, Username: username,
			ObtainedAt: time.Now().UTC(), Exchange: result,
		})
	})
}

// LoadIdMSAccount decrypts the saved snapshot and checks its device binding.
// It makes no network request and does not claim that saved tokens remain valid.
func (d *Device) LoadIdMSAccount(ctx context.Context) (account *SavedIdMSAccount, err error) {
	err = d.run(ctx, false, func() error {
		account, err = loadAccount(d.store.dir, d.state.AndroidID)
		return err
	})
	if err != nil {
		account.Destroy()
		return nil, err
	}
	return account, nil
}

func saveAccount(dir string, account *SavedIdMSAccount) error {
	if account == nil || !validAccount(account, account.DeviceID) {
		return errors.New("invalid IdMS account snapshot")
	}
	plain, err := json.Marshal(account)
	if err != nil {
		return errors.New("cannot encode IdMS account snapshot")
	}
	defer clear(plain)
	raw, err := protectState(dir, "idms", plain, false)
	if err != nil {
		return err
	}
	defer clear(raw)
	return securefile.Write(filepath.Join(dir, "idms.state"), raw)
}

func loadAccount(dir, deviceID string) (*SavedIdMSAccount, error) {
	invalid := errors.New("IdMS account snapshot unavailable, invalid or bound to another device")
	f, err := os.Open(filepath.Join(dir, "idms.state"))
	if err != nil {
		return nil, invalid
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, stateLimit+1))
	defer clear(raw)
	if err != nil || len(raw) > stateLimit {
		return nil, invalid
	}
	plain, err := protectState(dir, "idms", raw, true)
	if err != nil {
		return nil, invalid
	}
	defer clear(plain)
	a := new(SavedIdMSAccount)
	if json.Unmarshal(plain, a) != nil || !validAccount(a, deviceID) {
		a.Destroy()
		return nil, invalid
	}
	return a, nil
}
