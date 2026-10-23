// Package dirlock provides exclusive ownership using a lock directory.
package dirlock

import (
	"errors"
	"os"
	"sync"
)

// ErrBusy means a lock exists or could not be created. A lock left by a crashed
// process must be removed manually after confirming the former owner has exited.
var ErrBusy = errors.New("state unavailable or in use; an existing lock is never stolen")

// Lock must not be copied. Close releases ownership once.
type Lock struct {
	mu   sync.Mutex
	path string
}

func Acquire(path string) (*Lock, error) {
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, ErrBusy
	}
	return &Lock{path: path}, nil
}

func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path == "" {
		return nil
	}
	if err := os.Remove(l.path); err != nil {
		return errors.New("cannot release state lock")
	}
	l.path = ""
	return nil
}
