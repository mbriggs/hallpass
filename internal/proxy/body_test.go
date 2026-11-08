package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/peer"
)

// A client that sends headers and never the body gets an answer once
// bodyWait passes, instead of holding a handler for as long as it likes.
func TestBodyThatNeverArrives(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(t.TempDir(), "gh.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &Server{
		Config:    &config.Config{Token: &config.Token{Login: "mbriggs"}},
		Token:     testToken,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
		bodyWait:  100 * time.Millisecond,
	}
	go srv.ServeGH(ln)

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /repos/acme/widgets/issues HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 100\r\n\r\n")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Errorf("status %d, want 408", resp.StatusCode)
	}
}
