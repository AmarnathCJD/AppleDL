package dirlock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func TestExclusiveAcrossProcesses(t *testing.T) {
	if path := os.Getenv("APPLE_TEST_LOCK"); path != "" {
		if l, err := Acquire(path); !errors.Is(err, ErrBusy) {
			if l != nil {
				l.Close()
			}
			t.Fatal("child acquired owned lock")
		}
		return
	}
	path := filepath.Join(t.TempDir(), "state.lock")
	l, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestExclusiveAcrossProcesses$")
	cmd.Env = append(os.Environ(), "APPLE_TEST_LOCK="+path)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v: %s", err, b)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	next, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(path); !errors.Is(err, ErrBusy) {
		t.Fatal("old owner removed new lock")
	}
}

func TestAbandonedLockNotStolen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "abandoned.lock")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(path); !errors.Is(err, ErrBusy) {
		t.Fatal("existing lock stolen")
	}
}
