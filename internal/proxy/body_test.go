package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
		Log:       slog.New(slog.DiscardHandler),
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

// A body of up to 4 MiB reaches GitHub whole, with the default bodyWait.
// One byte more is refused, not cut short.
func TestBodySizeLimit(t *testing.T) {
	t.Parallel()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"number":2}`)
	}))
	t.Cleanup(up.Close)
	client := ghClient(t, up.URL, config.Repo{Match: "acme/widgets"})
	for size, want := range map[int]int{4 << 20: 201, 4<<20 + 1: 413} {
		pre := `{"title":"t","head":"b","base":"main","body":"`
		body := pre + strings.Repeat("x", size-len(pre)-2) + `"}`
		req, _ := http.NewRequest(http.MethodPost, "http://api.github.com/repos/acme/widgets/pulls", strings.NewReader(body))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		msg, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%d-byte body: %d %s", size, resp.StatusCode, msg)
		}
	}
}
