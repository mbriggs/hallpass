package sshgate

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/peer"
)

// serveLimited starts a gate on a Unix socket with tight limits and returns
// a way to connect to it.
func serveLimited(t *testing.T, conns int, wait time.Duration) func() net.Conn {
	sock := filepath.Join(t.TempDir(), "ssh.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{
		Config:    &config.Config{},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
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
