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
// answer, not only at the top of /repos/o/r, and in what a write returns.
func TestStripsCloneTokensAtAnyDepth(t *testing.T) {
	t.Parallel()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch r.Method + " " + r.URL.Path {
		case "POST /repos/acme/widgets/pulls":
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"number":2,"base":{"repo":{"temp_clone_token":"T6"}},"head":{"repo":{"temp_clone_token":"T7"}}}`)
		case "POST /repos/acme/widgets/actions/workflows/ci.yml/dispatches":
			w.WriteHeader(http.StatusNoContent)
		case "GET /repos/acme/widgets":
			io.WriteString(w, `{"full_name":"acme/widgets","temp_clone_token":"T1","parent":{"full_name":"acme/up","temp_clone_token":"T2"},"source":{"temp_clone_token":"T3"}}`)
		case "GET /repos/acme/widgets/pulls":
			io.WriteString(w, `[{"number":1,"body":"<b>&</b>","base":{"repo":{"temp_clone_token":"T4"}},"head":{"repo":{"temp_clone_token":"T5","id":12345678901234567}}}]`)
		}
	}))
	t.Cleanup(up.Close)
	client := ghClient(t, up.URL, config.Repo{Match: "acme/widgets", Allow: []config.Grant{"workflow.dispatch"}})

	for _, c := range []struct {
		method, path, body string
		status             int
		keep               []string
	}{
		{"GET", "/repos/acme/widgets", "", 200, []string{`"full_name":"acme/up"`}},
		{"GET", "/repos/acme/widgets/pulls", "", 200, []string{`"body":"<b>&</b>"`, `"id":12345678901234567`}},
		{"POST", "/repos/acme/widgets/pulls", `{"title":"t","head":"b","base":"main"}`, 201, []string{`"number":2`}},
		{"POST", "/repos/acme/widgets/actions/workflows/ci.yml/dispatches", `{"ref":"main"}`, 204, nil},
	} {
		req, _ := http.NewRequest(c.method, "http://api.github.com"+c.path, strings.NewReader(c.body))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.status || strings.Contains(string(body), "temp_clone_token") {
			t.Errorf("%s %s: %d %s", c.method, c.path, resp.StatusCode, body)
		}
		for _, k := range c.keep {
			if !strings.Contains(string(body), k) {
				t.Errorf("%s %s: lost %s: %s", c.method, c.path, k, body)
			}
		}
	}
}

// ghClient serves the gh socket in front of api, for the token's user
// mbriggs, with repo in the allowlist, and returns a client for it.
func ghClient(t *testing.T, api string, repo config.Repo) *http.Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "gh.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &Server{
		Config:    &config.Config{Token: &config.Token{Login: "mbriggs"}, Repos: []config.Repo{repo}, APIURL: api},
		Token:     testToken,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
	}
	go srv.ServeGH(ln)
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
}
