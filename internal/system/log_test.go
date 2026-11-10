package system

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newsyslog leaves hallpass.log.0.gz through hallpass.log.4.gz next to the
// log, the highest number the oldest.
func TestOpenLogFilesOrder(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "hallpass.log")
	writeGz := func(name, body string) {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		zw := gzip.NewWriter(f)
		_, _ = zw.Write([]byte(body))
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	writeGz("hallpass.log.10.gz", "ten\n")
	writeGz("hallpass.log.2.gz", "two\n")
	writeGz("hallpass.log.0.gz", "zero") // no final newline
	if err := os.WriteFile(filepath.Join(dir, "hallpass.log.1"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte("now\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hallpass.log.bak"), []byte("not a copy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, base); got != "ten two one zero now" {
		t.Errorf("read %q", got)
	}

	// Just after newsyslog moves the log, before the broker writes again,
	// only the copies are there.
	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, base); got != "ten two one zero" {
		t.Errorf("without the log, read %q", got)
	}
}

func TestOpenLogFilesMissing(t *testing.T) {
	if _, err := openLogFiles(filepath.Join(t.TempDir(), "hallpass.log")); err == nil {
		t.Error("opened a log that isn't there")
	}
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	r, err := openLogFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(b)), " ")
}
