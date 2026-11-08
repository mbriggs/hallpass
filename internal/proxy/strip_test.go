package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/peer"
)

// A private repo object carries a clone credential wherever it appears in an
// answer, not only at the top of /repos/o/r.
func TestStripsCloneTokensAtAnyDepth(t *testing.T) {
	t.Parallel()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch r.URL.Path {
		case "/repos/acme/widgets":
			io.WriteString(w, `{"full_name":"acme/widgets","temp_clone_token":"T1","parent":{"full_name":"acme/up","temp_clone_token":"T2"},"source":{"temp_clone_token":"T3"}}`)
		case "/repos/acme/widgets/pulls":
			io.WriteString(w, `[{"number":1,"body":"<b>&</b>","base":{"repo":{"temp_clone_token":"T4"}},"head":{"repo":{"temp_clone_token":"T5","id":12345678901234567}}}]`)
		}
	}))
	t.Cleanup(up.Close)
	sock := filepath.Join(t.TempDir(), "gh.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &Server{
		Config:    &config.Config{Token: &config.Token{Login: "mbriggs"}, Repos: []config.Repo{{Match: "acme/widgets"}}, APIURL: up.URL},
		Token:     testToken,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
	}
	go srv.ServeGH(ln)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}

	for path, keep := range map[string][]string{
		"/repos/acme/widgets":       {`"full_name":"acme/up"`},
		"/repos/acme/widgets/pulls": {`"body":"<b>&</b>"`, `"id":12345678901234567`},
	} {
		resp, err := client.Get("http://api.github.com" + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || strings.Contains(string(body), "temp_clone_token") {
			t.Errorf("%s: %d %s", path, resp.StatusCode, body)
		}
		for _, k := range keep {
			if !strings.Contains(string(body), k) {
				t.Errorf("%s: lost %s: %s", path, k, body)
			}
		}
	}
}
