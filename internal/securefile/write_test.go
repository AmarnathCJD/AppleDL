package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementAndFailedCommitCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session")
	for _, value := range []string{"old", "new"} {
		if err := Write(path, []byte(value)); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != value {
			t.Fatal("incorrect replacement")
		}
	}
	blocked := filepath.Join(dir, "directory")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(blocked, "preserved")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Write(blocked, []byte("bad")); err == nil {
		t.Fatal("replaced directory")
	}
	if b, err := os.ReadFile(marker); err != nil || string(b) != "keep" {
		t.Fatal("failed commit damaged original")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("temporary file leaked")
	}
}
