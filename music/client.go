// Package music provides a standalone Apple Music client implemented in Go.
// Local device state is encrypted; portable session exports are bearer credentials.
package music

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	am "github.com/AmarnathCJD/AppleDL"
	"github.com/AmarnathCJD/AppleDL/internal/dirlock"
	"github.com/AmarnathCJD/AppleDL/standalone"
)

const DefaultSessionFile = "applemusic.dat"

var (
	ErrClosed          = errors.New("music client is closed")
	ErrSessionRequired = errors.New("saved session or account login required")
	ErrAccountMismatch = errors.New("saved session belongs to a different account")
	ErrSongNotFound    = errors.New("song was not found")
)

// Config is copied by New. Credentials are used only when no saved session is
// available and are never retained in the client or exported session.
type Config struct {
	Username    string
	Password    string
	Session     string       // explicit export, takes precedence over SessionFile
	SessionFile string       // defaults to applemusic.dat in the current directory
	StateDir    string       // defaults to .applemusic/device in the current directory
	Country     string       // catalog country; defaults to us, or the imported session's country
	HTTPClient  *http.Client // optional trusted transport; do not log credential headers
	Workers     int          // 0: min(GOMAXPROCS, 16); explicit range 1..64
	Progress    io.Writer    // optional redacted progress; calls are serialized
}

func (Config) String() string   { return "music.Config{redacted}" }
func (Config) GoString() string { return "music.Config{redacted}" }

type clientState struct {
	device   *standalone.Device
	media    *am.MediaClient
	username string
	ownedDir string // only generated import staging directories are removed
}

// Client serializes operations and session changes. ALAC samples are parallel
// within a download. Close waits for the current operation; cancel its context
// to interrupt it. A Client must not be copied after first use.
type Client struct {
	gate            chan struct{}
	cfg             Config
	countryExplicit bool
	protocol        *am.Client
	state           *clientState
	closed          bool
	sessionLock     *dirlock.Lock
}

func (*Client) String() string   { return "music.Client{redacted}" }
func (*Client) GoString() string { return "music.Client{redacted}" }

func validCountry(country string) bool {
	return len(country) == 2 && country[0] >= 'a' && country[0] <= 'z' && country[1] >= 'a' && country[1] <= 'z'
}

// New prefers an explicit session, then the session file, then existing device
// state. It validates saved commerce credentials by requesting a fresh media
// token. Invalid files/network failures are returned without a password retry.
// With no saved state or credentials, New returns an empty client for ImportSession.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Workers < 0 || cfg.Workers > 64 {
		return nil, errors.New("workers must be 0 through 64")
	}
	if cfg.Country != "" && !validCountry(cfg.Country) {
		return nil, errors.New("country must be a lowercase two-letter code")
	}
	if cfg.SessionFile == "" {
		cfg.SessionFile = DefaultSessionFile
	}
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(".applemusic", "device")
	}
	var err error
	cfg.SessionFile, err = filepath.Abs(cfg.SessionFile)
	if err != nil {
		return nil, errors.New("invalid session path")
	}
	cfg.StateDir, err = filepath.Abs(cfg.StateDir)
	if err != nil {
		return nil, errors.New("invalid state path")
	}
	if cfg.Progress == nil {
		cfg.Progress = io.Discard
	}
	if cfg.HTTPClient != nil {
		copy := *cfg.HTTPClient
		cfg.HTTPClient = &copy
	}
	p, err := am.New(am.Config{HTTPClient: cfg.HTTPClient})
	if err != nil {
		return nil, err
	}
	username, password, encoded := cfg.Username, cfg.Password, cfg.Session
	cfg.Username, cfg.Password, cfg.Session = "", "", ""
	c := &Client{gate: make(chan struct{}, 1), cfg: cfg, protocol: p, countryExplicit: cfg.Country != ""}
	if err := c.validateSessionPath(cfg.SessionFile); err != nil {
		return nil, err
	}
	c.sessionLock, err = dirlock.Acquire(cfg.SessionFile + ".lock")
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			_ = c.sessionLock.Close()
		}
	}()
	if encoded == "" {
		encoded, err = readSessionFile(cfg.SessionFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		err = nil // A missing optional session file is an empty client, not a failure.
	}
	if encoded != "" {
		err = c.importSession(ctx, encoded, username)
	} else {
		if c.cfg.Country == "" {
			c.cfg.Country = "us"
		}
		_, statErr := os.Stat(filepath.Join(cfg.StateDir, "commerce.state"))
		switch {
		case statErr == nil:
			err = c.openSaved(ctx, username)
		case !errors.Is(statErr, os.ErrNotExist):
			err = errors.New("cannot inspect saved device state")
		case username != "" || password != "":
			err = c.login(ctx, username, password)
		}
	}
	if err != nil {
		if c.state != nil {
			_ = c.releaseState(c.state, true)
		}
		return nil, err
	}
	ready = true
	return c, nil
}

func (c *Client) lock(ctx context.Context) error {
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		c.unlock()
		return err
	}
	if c.closed {
		c.unlock()
		return ErrClosed
	}
	return nil
}
func (c *Client) unlock() { <-c.gate }

func (c *Client) runtimeConfig(dir string) standalone.Config { return standalone.Config{StateDir: dir} }

func (c *Client) openSaved(ctx context.Context, username string) error {
	d, err := standalone.Open(ctx, c.runtimeConfig(c.cfg.StateDir))
	if err != nil {
		return err
	}
	s, err := c.connectSaved(ctx, d, username)
	if err != nil {
		_ = d.Close()
		return err
	}
	c.state = s
	return c.saveSession(c.cfg.SessionFile)
}

func sameAccount(expected, actual string) bool {
	return expected == "" || strings.EqualFold(expected, actual)
}

// Login uses one password exchange only when this client has no session. A
// matching active session is refreshed instead, even if a password is supplied.
func (c *Client) Login(ctx context.Context, username, password string) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.state != nil {
		if !sameAccount(username, c.state.username) {
			return ErrAccountMismatch
		}
		return c.refresh(ctx)
	}
	return c.login(ctx, username, password)
}

// Refresh renews the media token from saved commerce credentials, without a
// password exchange. It preserves the current session on failure.
func (c *Client) Refresh(ctx context.Context) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	return c.refresh(ctx)
}
func (c *Client) refresh(ctx context.Context) error {
	if c.state == nil {
		return ErrSessionRequired
	}
	s, err := c.connectSaved(ctx, c.state.device, c.state.username)
	if err != nil {
		return err
	}
	c.state.media = s.media
	return nil
}

func (c *Client) releaseState(s *clientState, remove bool) error {
	if s == nil {
		return nil
	}
	err := s.device.Close()
	if err == nil && remove && s.ownedDir != "" {
		err = os.RemoveAll(s.ownedDir)
	}
	s.media, s.username = nil, ""
	return err
}

// Close saves the current portable session and releases runtime memory. Failed
// saves preserve the staging state on disk for recovery. Close is idempotent.
func (c *Client) Close() error {
	c.gate <- struct{}{}
	defer c.unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	var err error
	if c.state != nil {
		err = c.saveSession(c.cfg.SessionFile)
		err = errors.Join(err, c.releaseState(c.state, err == nil))
	}
	c.state = nil
	return errors.Join(err, c.sessionLock.Close())
}
