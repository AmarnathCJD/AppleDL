package music

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AmarnathCJD/AppleDL/internal/dirlock"
	"github.com/AmarnathCJD/AppleDL/internal/securefile"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

const maxSessionBytes = 48 << 20

type sessionEnvelope struct {
	Version int    `json:"version"`
	Country string `json:"country"`
	Device  string `json:"device"` // portable bearer credentials, not encrypted
}

func readSessionFile(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", os.ErrNotExist
	}
	if err != nil {
		return "", errors.New("cannot open session file")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSessionBytes+1))
	defer clear(b)
	if err != nil || len(b) == 0 || len(b) > maxSessionBytes {
		return "", errors.New("invalid session file size")
	}
	return string(b), nil
}

func decodeEnvelope(encoded string) (*sessionEnvelope, error) {
	if len(encoded) == 0 || len(encoded) > maxSessionBytes {
		return nil, errors.New("invalid session size")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	defer clear(b)
	if err != nil {
		return nil, errors.New("invalid URL-safe session encoding")
	}
	var e sessionEnvelope
	if json.Unmarshal(b, &e) != nil || e.Version != 1 || !validCountry(e.Country) || e.Device == "" {
		return nil, errors.New("invalid or unsupported session envelope")
	}
	return &e, nil
}

func (c *Client) exportSession() (string, error) {
	if c.state == nil {
		return "", ErrSessionRequired
	}
	device, err := c.state.device.ExportSession(context.Background())
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(sessionEnvelope{Version: 1, Country: c.cfg.Country, Device: device})
	defer clear(b)
	if err != nil {
		return "", errors.New("cannot encode session envelope")
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	if len(encoded) > maxSessionBytes {
		return "", errors.New("session exceeds size limit")
	}
	return encoded, nil
}

// ExportSession returns portable URL-safe Base64 containing device, IdMS and
// commerce state. It is not encrypted: anyone with the string can reuse the
// session. Treat exports and saved .dat files like passwords.
func (c *Client) ExportSession() (string, error) {
	if err := c.lock(context.Background()); err != nil {
		return "", err
	}
	defer c.unlock()
	return c.exportSession()
}

func (c *Client) saveSession(path string) error {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return errors.New("invalid session path")
	}
	if err := c.validateSessionPath(path); err != nil {
		return err
	}
	if !c.ownsSessionPath(path) {
		lock, err := dirlock.Acquire(path + ".lock")
		if err != nil {
			return err
		}
		defer lock.Close()
	}
	encoded, err := c.exportSession()
	if err != nil {
		return err
	}
	return securefile.Write(path, []byte(encoded))
}

// Compare the lock directories too: the filesystem may treat differently cased
// names or symlinked parent directories as the same session destination.
func (c *Client) ownsSessionPath(path string) bool {
	if path == c.cfg.SessionFile {
		return true
	}
	owned, err := os.Stat(c.cfg.SessionFile + ".lock")
	if err != nil {
		return false
	}
	other, err := os.Stat(path + ".lock")
	return err == nil && os.SameFile(owned, other)
}

func insidePath(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (c *Client) validateSessionPath(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errors.New("invalid session path")
	}
	if insidePath(c.cfg.StateDir, absolute) || (c.state != nil && c.state.ownedDir != "" && insidePath(c.state.ownedDir, absolute)) {
		return errors.New("session file must be outside the device state directory")
	}
	return nil
}

// SaveSession writes the export through a synced temporary file and os.Rename.
// Replacement atomicity depends on the OS/filesystem. An empty filename uses
// SessionFile. The parent directory must exist; concurrent writers are rejected.
func (c *Client) SaveSession(filename string) error {
	if err := c.lock(context.Background()); err != nil {
		return err
	}
	defer c.unlock()
	if filename == "" {
		filename = c.cfg.SessionFile
	}
	return c.saveSession(filename)
}

// ImportSession stages and validates the session online before replacing the
// current client. Failed validation leaves the old client and file intact.
func (c *Client) ImportSession(ctx context.Context, encoded string) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	return c.importSession(ctx, encoded, "")
}

// ImportSessionFromFile uses the configured/default file when filename is empty.
func (c *Client) ImportSessionFromFile(ctx context.Context, filename string) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if filename == "" {
		filename = c.cfg.SessionFile
	}
	encoded, err := readSessionFile(filename)
	if err != nil {
		return err
	}
	return c.importSession(ctx, encoded, "")
}

func (c *Client) importSession(ctx context.Context, encoded, username string) error {
	e, err := decodeEnvelope(encoded)
	if err != nil {
		return err
	}
	parent := filepath.Dir(c.cfg.StateDir)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return errors.New("cannot create session staging parent")
	}
	stage, err := os.MkdirTemp(parent, "import-")
	if err != nil {
		return errors.New("cannot create session staging directory")
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(stage)
		}
	}()
	d, err := standalone.RestoreSession(ctx, c.runtimeConfig(filepath.Join(stage, "device")), e.Device)
	if err != nil {
		return err
	}
	previousCountry := c.cfg.Country
	if !c.countryExplicit {
		c.cfg.Country = e.Country
	}
	s, err := c.connectSaved(ctx, d, username)
	if err != nil {
		c.cfg.Country = previousCountry
		_ = d.Close()
		return err
	}
	s.ownedDir = stage
	previous := c.state
	c.state = s
	if err := c.saveSession(c.cfg.SessionFile); err != nil {
		c.state = previous
		c.cfg.Country = previousCountry
		_ = d.Close()
		return err
	}
	ok = true
	return c.releaseState(previous, true)
}
