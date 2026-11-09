package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/broker"
	"github.com/mbriggs/hallpass/internal/config"
)

// The broker's own check decides who may use the gh socket: a uid the config
// doesn't list is refused, and so is a peer the kernel doesn't report.
func TestRefusesUnpermittedPeers(t *testing.T) {
	t.Parallel()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"full_name":"acme/widgets"}`)
	}))
	t.Cleanup(up.Close)
	me := uint32(os.Getuid())
	for _, c := range []struct {
		network string
		uids    []uint32
		status  int
	}{
		{"unix", []uint32{me}, 200},
		{"unix", []uint32{me + 1}, 403},
		// Over TCP there's no peer to report. Its zero uid is listed, and
		// mustn't count.
		{"tcp", []uint32{0, me}, 403},
	} {
		cfg := &config.Config{UIDs: c.uids, Token: &config.Token{Login: "mbriggs"}, Repos: []config.Repo{{Match: "acme/widgets"}}, APIURL: up.URL}
		client := serveGH(t, c.network, &Server{
			Config:    cfg,
			Token:     testToken,
			Log:       slog.New(slog.DiscardHandler),
			Permitted: (&broker.Server{Config: cfg}).Permitted,
		})
		resp, err := client.Get("http://api.github.com/repos/acme/widgets")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.status || c.status == 403 && !strings.Contains(string(body), "this uid may not use hallpass") {
			t.Errorf("%s peer, uids %v: %d %s", c.network, c.uids, resp.StatusCode, body)
		}
	}
}

// Agents may read a read-only repo, over REST and GraphQL, and not write to
// it.
func TestReadOnlyRepo(t *testing.T) {
	t.Parallel()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{"name":"widgets"}}}`)
	}))
	t.Cleanup(up.Close)
	client := ghClient(t, up.URL, config.Repo{Match: "acme/widgets", Access: "read"})
	for _, c := range []struct {
		method, path, body string
		status             int
		want               string
	}{
		{"POST", "/graphql", `{"query":"query{repository(owner:\"acme\",name:\"widgets\"){name}}"}`, 200, `"name":"widgets"`},
		{"POST", "/repos/acme/widgets/issues", `{"title":"t"}`, 403, "agents may only read acme/widgets"},
	} {
		req, _ := http.NewRequest(c.method, "http://api.github.com"+c.path, strings.NewReader(c.body))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.status || !strings.Contains(string(body), c.want) {
			t.Errorf("%s %s: %d %s", c.method, c.path, resp.StatusCode, body)
		}
	}
}
