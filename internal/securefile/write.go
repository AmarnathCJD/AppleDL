// Package securefile commits sensitive files without exposing partial writes.
package securefile

import (
	"errors"
	"os"
	"path/filepath"
)

// Write replaces path using a same-directory temporary file, Sync and Rename.
// The parent must already exist. Replacement atomicity is that of os.Rename:
// it is not guaranteed on every operating system or filesystem.
func Write(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".session-*.tmp")
	if err != nil {
		return errors.New("cannot create session temporary file")
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return errors.New("cannot write session file")
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return errors.New("cannot commit session file")
	}
	return nil
}
