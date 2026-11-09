package sshgate

import (
	"bytes"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/peer"
)

// socketPath is a path for a test's Unix socket. macOS caps socket paths at
// 104 bytes, and t.TempDir() there is a long path under /var/folders, so
// the directory goes under /tmp.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hpgate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "ssh.sock")
}

// serveLimited starts a gate on a Unix socket with tight limits and returns
// a way to connect to it.
func serveLimited(t *testing.T, conns int, wait time.Duration) func() net.Conn {
	t.Helper()
	sock := socketPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{
		Config:    &config.Config{},
		Log:       slog.New(slog.DiscardHandler),
		Permitted: func(peer.Peer) bool { return true },
		limits:    limits{conns: conns, headerWait: wait},
	}
	go s.Serve(ln)
	return func() net.Conn {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
}

// stderr reads frames until the exit frame and returns what came on stderr.
func stderr(t *testing.T, c net.Conn) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var b strings.Builder
	for {
		kind, data, err := ReadFrame(c)
		if err != nil {
			t.Fatalf("reading frames: %v (stderr so far %q)", err, b.String())
		}
		switch kind {
		case FrameStderr:
			b.Write(data)
		case FrameExit:
			return b.String()
		}
	}
}

// A connection past the cap is refused at once instead of queuing.
func TestGateRefusesPastConnectionCap(t *testing.T) {
	dial := serveLimited(t, 1, 3*time.Second)
	dial() // holds the one slot, waiting to send its header
	time.Sleep(50 * time.Millisecond)
	if got := stderr(t, dial()); !strings.Contains(got, "too many git connections") {
		t.Errorf("second connection got %q", got)
	}
}

// A client that never sends its header is cut off after headerWait.
func TestGateCutsSilentClient(t *testing.T) {
	dial := serveLimited(t, 4, 200*time.Millisecond)
	start := time.Now()
	if got := stderr(t, dial()); !strings.Contains(got, "malformed request") {
		t.Errorf("silent client got %q", got)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("silent client held for %v", d)
	}
}

// The copy of GitHub's push answer that the broker keeps stops at its cap,
// and the writes past it still count as written.
func TestCappedStopsAtMax(t *testing.T) {
	var buf bytes.Buffer
	c := &capped{&buf, 4}
	for _, s := range []string{"abc", "def", "ghi"} {
		if n, err := c.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
	}
	if buf.String() != "abcd" {
		t.Errorf("kept %q, want %q", buf.String(), "abcd")
	}
}
