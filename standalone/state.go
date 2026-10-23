package standalone

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AmarnathCJD/AppleDL/internal/dirlock"
	"github.com/AmarnathCJD/AppleDL/internal/securefile"
)

const stateLimit = 24 << 20

type diskState struct {
	Version   int               `json:"version"`
	AndroidID string            `json:"android_id"`
	Files     map[string][]byte `json:"files"`
	Dirs      map[string]bool   `json:"dirs"`
	Modified  map[string]int64  `json:"modified,omitempty"`
}

func (diskState) String() string   { return "device state (redacted)" }
func (diskState) GoString() string { return "device state (redacted)" }

type stateStore struct {
	dir  string
	lock *dirlock.Lock
}

func openState(dir string) (*stateStore, *diskState, error) {
	if !filepath.IsAbs(dir) {
		return nil, nil, errors.New("device state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, errors.New("create device directory failed")
	}
	lock, err := dirlock.Acquire(filepath.Join(dir, "device.lock"))
	if err != nil {
		return nil, nil, err
	}
	s := &stateStore{dir: dir, lock: lock}
	fail := func() (*stateStore, *diskState, error) {
		s.close()
		return nil, nil, errors.New("device state cannot be loaded; existing state was preserved")
	}
	f, err := os.Open(filepath.Join(dir, "device.state"))
	if os.IsNotExist(err) {
		// Never silently replace a legacy device identity.
		for _, name := range []string{"device.dpapi", "idms.dpapi", "commerce.dpapi", "idms.state", "commerce.state"} {
			if _, e := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(e) {
				return fail()
			}
		}
		var id [8]byte
		if _, err := rand.Read(id[:]); err != nil {
			return fail()
		}
		state := &diskState{Version: 1, AndroidID: hex.EncodeToString(id[:]), Files: map[string][]byte{}, Dirs: map[string]bool{"/adi": true}, Modified: map[string]int64{}}
		if s.save(state) != nil {
			return fail()
		}
		return s, state, nil
	}
	if err != nil {
		return fail()
	}
	raw, err := io.ReadAll(io.LimitReader(f, stateLimit+1))
	f.Close()
	if err != nil || len(raw) > stateLimit {
		return fail()
	}
	plain, err := protectState(dir, "device", raw, true)
	clear(raw)
	if err != nil {
		return fail()
	}
	defer clear(plain)
	var state diskState
	if json.Unmarshal(plain, &state) != nil || !validDiskState(&state) {
		return fail()
	}
	return s, &state, nil
}

func validDiskState(s *diskState) bool {
	if s.Version != 1 || len(s.AndroidID) != 16 || strings.ToLower(s.AndroidID) != s.AndroidID {
		return false
	}
	if _, err := hex.DecodeString(s.AndroidID); err != nil {
		return false
	}
	if s.Files == nil || !s.Dirs["/adi"] || len(s.Dirs) > 128 || len(s.Files) > 128 {
		return false
	}
	total := 0
	for path, stamp := range s.Modified {
		if _, exists := s.Files[path]; !exists || stamp <= 0 {
			return false
		}
	}
	for path, yes := range s.Dirs {
		if !yes || !validVirtualPath(path) {
			return false
		}
		if path != "/adi" && !s.Dirs[path[:strings.LastIndexByte(path, '/')]] {
			return false
		}
	}
	for path, data := range s.Files {
		if !validVirtualPath(path) || s.Dirs[path] || !s.Dirs[path[:strings.LastIndexByte(path, '/')]] || len(data) > bufferLimit {
			return false
		}
		total += len(data)
	}
	return total <= 16<<20
}

func (s *stateStore) save(state *diskState) error {
	if !validDiskState(state) {
		return errors.New("invalid device state")
	}
	plain, err := json.Marshal(state)
	if err != nil {
		return errors.New("encode device state failed")
	}
	defer clear(plain)
	raw, err := protectState(s.dir, "device", plain, false)
	if err != nil {
		return err
	}
	defer clear(raw)
	return securefile.Write(filepath.Join(s.dir, "device.state"), raw)
}

func (s *stateStore) close() { _ = s.lock.Close() }
