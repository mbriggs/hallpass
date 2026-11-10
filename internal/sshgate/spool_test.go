package sshgate

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The spool starts by clearing packs a crash left, and leaves the rest.
func TestOpenSpoolClearsLeftovers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	os.Mkdir(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "pack-123"), []byte("PACK"), 0o600)
	os.WriteFile(filepath.Join(dir, "other"), nil, 0o600)
	if _, err := OpenSpool(dir, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pack-123")); !os.IsNotExist(err) {
		t.Errorf("left the crashed pack: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "other")); err != nil {
		t.Errorf("removed a file that isn't a pack: %v", err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("spool dir mode %v, want 0700", fi.Mode().Perm())
	}
}

type failAfter struct {
	r   io.Reader
	err error
}

func (f *failAfter) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err == io.EOF {
		return n, f.err
	}
	return n, err
}

// The spool holds at most its budget across pushes. A push gives its share
// back when it closes, or when reading it fails partway, and its file never
// has a name in the directory.
func TestSpoolBudget(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSpool(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.take(bytes.NewReader([]byte("PACK123456")))
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("a held pack has a name: %v", left[0].Name())
	}
	got, _ := io.ReadAll(a)
	if string(got) != "PACK123456" {
		t.Errorf("read back %q", got)
	}
	if _, err := s.take(bytes.NewReader([]byte("x"))); !errors.Is(err, errSpoolFull) {
		t.Errorf("take past the budget = %v, want errSpoolFull", err)
	}
	a.release()
	gone := errors.New("client went away")
	if _, err := s.take(&failAfter{bytes.NewReader([]byte("PACK1")), gone}); !errors.Is(err, gone) {
		t.Errorf("take of a broken stream = %v", err)
	}
	b, err := s.take(bytes.NewReader([]byte("PACK123456")))
	if err != nil {
		t.Fatalf("budget not returned: %v", err)
	}
	b.release()
	if s.used != 0 {
		t.Errorf("spool counts %d bytes after every push closed", s.used)
	}
}
