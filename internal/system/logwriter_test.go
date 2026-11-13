package system

import (
	"os"
	"path/filepath"
	"testing"
)

// openFollow opens path for appending, as launchd opens the broker's stderr,
// and follows it.
func openFollow(t *testing.T, path string) *followWriter {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	w := newFollowWriter(path, f)
	t.Cleanup(func() { _ = w.f.Close() })
	return w
}

func writeLines(t *testing.T, w *followWriter, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if _, err := w.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("%s = %q, want %q", filepath.Base(path), got, want)
	}
}

// rotate does what newsyslog does: renames the log, and when create is set,
// makes a new empty file in its place.
func rotate(t *testing.T, path string, create bool) {
	t.Helper()
	if err := os.Rename(path, path+".0"); err != nil {
		t.Fatal(err)
	}
	if create {
		if err := os.WriteFile(path, nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFollowWriterReopensAfterRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hallpass.log")
	w := openFollow(t, path)
	writeLines(t, w, "one", "two")
	rotate(t, path, true)
	writeLines(t, w, "three", "four")

	assertFile(t, path+".0", "one\ntwo\n")
	assertFile(t, path, "three\nfour\n")
}

// In /var/log, which root owns, the broker can't create the new file, so it
// writes to the old one until newsyslog has made it.
func TestFollowWriterWaitsForNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hallpass.log")
	w := openFollow(t, path)
	w.create = false
	writeLines(t, w, "one")
	rotate(t, path, false)
	writeLines(t, w, "two")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the writer made %s without leave to: %v", path, err)
	}
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	writeLines(t, w, "three")

	assertFile(t, path+".0", "one\ntwo\n")
	assertFile(t, path, "three\n")
}

// In a directory the broker owns, it makes the new file itself.
func TestFollowWriterCreatesInOwnDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hallpass.log")
	w := openFollow(t, path)
	if !w.create {
		t.Fatal("the writer won't create the log in a directory it owns")
	}
	writeLines(t, w, "one")
	rotate(t, path, false)
	writeLines(t, w, "two")

	assertFile(t, path+".0", "one\n")
	assertFile(t, path, "two\n")
}
