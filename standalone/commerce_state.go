package standalone

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/internal/securefile"
	"howett.net/plist"
)

// SavedCommerceResponse preserves evidence and issued credentials, including
// unclassified responses. It does not certify a usable media session. The plist
// stays encoded to preserve integer/data types through JSON persistence.
// Serialization contains secrets; ordinary formatting is redacted.
type SavedCommerceResponse struct {
	Version     int         `json:"version"`
	DeviceID    string      `json:"device_id"`
	Username    string      `json:"username"`
	ObtainedAt  time.Time   `json:"obtained_at"`
	HTTPStatus  int         `json:"http_status"`
	HTTPHeaders http.Header `json:"http_headers"`
	FieldsPlist []byte      `json:"fields_plist"`
}

func (*SavedCommerceResponse) String() string   { return "SavedCommerceResponse{redacted}" }
func (*SavedCommerceResponse) GoString() string { return "SavedCommerceResponse{redacted}" }

func (s *SavedCommerceResponse) Destroy() {
	if s == nil {
		return
	}
	clear(s.FieldsPlist)
	clear(s.HTTPHeaders)
	*s = SavedCommerceResponse{}
}

// Response returns a new owned response; destroy it when finished. Observation
// must be recomputed from the evidence rather than trusting a saved verdict.
func (s *SavedCommerceResponse) Response() (*applemusic.CommerceResponse, error) {
	if s == nil {
		return nil, errors.New("missing saved commerce response")
	}
	r := &applemusic.CommerceResponse{HTTPStatus: s.HTTPStatus, HTTPHeaders: s.HTTPHeaders.Clone()}
	if _, err := plist.Unmarshal(s.FieldsPlist, &r.Fields); err != nil || len(r.Fields) == 0 {
		r.Destroy()
		return nil, errors.New("invalid saved commerce plist")
	}
	return r, nil
}

func validCommerceSnapshot(s *SavedCommerceResponse, deviceID string) bool {
	if s == nil || s.Version != 1 || deviceID == "" || s.DeviceID != deviceID ||
		s.Username == "" || len(s.Username) > 4096 || s.ObtainedAt.IsZero() ||
		s.HTTPStatus < 200 || s.HTTPStatus >= 300 || len(s.FieldsPlist) > stateLimit {
		return false
	}
	r, err := s.Response()
	if err != nil {
		return false
	}
	r.Destroy()
	return true
}

// SaveCommerceResponse stores a received HTTP 2xx plist under the local device
// lock. Call only after AuthenticatePET returns no error. Unknown statuses and
// challenges are retained, without upgrading them to a successful login.
func (d *Device) SaveCommerceResponse(ctx context.Context, username string, r *applemusic.CommerceResponse) error {
	if r == nil {
		return errors.New("missing commerce response")
	}
	return d.run(ctx, false, func() error {
		fields, err := plist.Marshal(r.Fields, plist.BinaryFormat)
		if err != nil {
			return errors.New("cannot encode commerce response")
		}
		s := &SavedCommerceResponse{Version: 1, DeviceID: d.state.AndroidID, Username: username,
			ObtainedAt: time.Now().UTC(), HTTPStatus: r.HTTPStatus, HTTPHeaders: r.HTTPHeaders.Clone(), FieldsPlist: fields}
		defer s.Destroy()
		return saveCommerceSnapshot(d.store.dir, s)
	})
}

// LoadCommerceResponse decrypts the snapshot and verifies its device binding.
// No token is sent to Apple and no validity claim is made.
func (d *Device) LoadCommerceResponse(ctx context.Context) (s *SavedCommerceResponse, err error) {
	err = d.run(ctx, false, func() error {
		s, err = loadCommerceSnapshot(d.store.dir, d.state.AndroidID)
		return err
	})
	if err != nil {
		s.Destroy()
		return nil, err
	}
	return s, nil
}

func saveCommerceSnapshot(dir string, s *SavedCommerceResponse) error {
	if s == nil || !validCommerceSnapshot(s, s.DeviceID) {
		return errors.New("invalid commerce snapshot")
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return errors.New("cannot encode commerce snapshot")
	}
	defer clear(plain)
	if len(plain) > stateLimit-4096 {
		return errors.New("commerce snapshot too large")
	}
	raw, err := protectState(dir, "commerce", plain, false)
	if err != nil {
		return err
	}
	defer clear(raw)
	if len(raw) > stateLimit {
		return errors.New("protected commerce snapshot too large")
	}
	return securefile.Write(filepath.Join(dir, "commerce.state"), raw)
}

func loadCommerceSnapshot(dir, deviceID string) (*SavedCommerceResponse, error) {
	invalid := errors.New("commerce snapshot unavailable, invalid or bound to another device")
	f, err := os.Open(filepath.Join(dir, "commerce.state"))
	if err != nil {
		return nil, invalid
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, stateLimit+1))
	defer clear(raw)
	if err != nil || len(raw) > stateLimit {
		return nil, invalid
	}
	plain, err := protectState(dir, "commerce", raw, true)
	if err != nil {
		return nil, invalid
	}
	defer clear(plain)
	s := new(SavedCommerceResponse)
	if json.Unmarshal(plain, s) != nil || !validCommerceSnapshot(s, deviceID) {
		s.Destroy()
		return nil, invalid
	}
	return s, nil
}
