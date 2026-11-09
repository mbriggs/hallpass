package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/peer"
)

// A read the allowlist or read tables don't cover goes to GitHub without the
// token, unless a policy denies it, and GitHub's refusal of it reads as
// hallpass's.
// anonServer serves srv's gh socket for this process's uid.
func anonServer(t *testing.T, srv *Server) *http.Client {
	t.Helper()
	srv.Log = slog.New(slog.DiscardHandler)
	srv.Permitted = func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) }
	return serveGH(t, "unix", srv)
}

func TestAnonymousReads(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+" auth="+r.Header.Get("Authorization"))
		mu.Unlock()
		anon := r.Header.Get("Authorization") == ""
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "3")
		switch {
		// Public: anyone sees it.
		case strings.HasPrefix(r.URL.Path, "/repos/cli/cli"), r.URL.Path == "/users/octocat":
			io.WriteString(w, `{"public":true}`)
		// Private: GitHub hides it without the token.
		case anon:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"message":"Not Found"}`)
		default:
			io.WriteString(w, `{"private":true}`)
		}
	}))
	t.Cleanup(up.Close)

	repos := []config.Repo{
		{Match: "acme/widgets", Deny: []config.Grant{"read:deployments"}},
		{Match: "acme/quiet", Deny: []config.Grant{"anonymous"}},
	}
	client := anonServer(t, &Server{Config: &config.Config{Repos: repos, APIURL: up.URL}, Token: testToken})
	denied := anonServer(t, &Server{Config: &config.Config{Repos: repos, APIURL: up.URL, Deny: []config.Grant{"anonymous"}}, Token: testToken})
	noToken := anonServer(t, &Server{Config: &config.Config{APIURL: up.URL}})

	for _, c := range []struct {
		name   string
		client *http.Client
		path   string
		status int
		want   string
		// reach is the Authorization GitHub saw, or "-" if it saw nothing.
		reach string
	}{
		{"unlisted public repo", client, "/repos/cli/cli/releases/latest", 200, `"public":true`, ""},
		{"path outside /repos", client, "/users/octocat", 200, `"public":true`, ""},
		{"read the tables don't cover", client, "/repos/acme/widgets/issues/1/timeline", 403, "Without a token, GitHub answered 404", ""},
		{"unlisted private repo", client, "/repos/acme/secret", 403, "acme/secret isn't in hallpass's allowlist", ""},
		{"no token on the machine", noToken, "/repos/cli/cli", 200, `"public":true`, ""},
		{"covered read keeps the token", client, "/repos/acme/widgets/pulls", 200, `"private":true`, "token " + testToken},
		{"dot segments never leave the broker", client, "/repos/cli/../acme/widgets", 403, "", "-"},
		{"read denied in a listed repo", client, "/repos/acme/widgets/deployments", 403, "The policy for acme/widgets denies it", "-"},
		{"anonymous denied in one repo", client, "/repos/acme/quiet/issues/1/timeline", 403, "doesn't allow reading", "-"},
		{"anonymous denied everywhere", denied, "/repos/cli/cli", 403, "cli/cli isn't in hallpass's allowlist", "-"},
		{"writes never go anonymous", client, "/repos/cli/cli/issues", 403, "isn't in hallpass's allowlist", "-"},
	} {
		mu.Lock()
		seen = nil
		mu.Unlock()
		method := "GET"
		if c.name == "writes never go anonymous" {
			method = "POST"
		}
		req, _ := http.NewRequest(method, "http://api.github.com"+c.path, strings.NewReader(`{"title":"t"}`))
		resp, err := c.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.status || !strings.Contains(string(body), c.want) {
			t.Errorf("%s: %d %s", c.name, resp.StatusCode, body)
		}
		mu.Lock()
		got := seen
		mu.Unlock()
		switch {
		case c.reach == "-" && len(got) > 0:
			t.Errorf("%s: reached GitHub: %v", c.name, got)
		case c.reach != "-" && (len(got) != 1 || got[0] != strings.SplitN(c.path, "?", 2)[0]+" auth="+c.reach):
			t.Errorf("%s: GitHub saw %v", c.name, got)
		}
	}
}

// Anonymous answers count against the machine's address, not the token, so
// they don't make the broker hold back the token's requests.
func TestAnonymousRateLeavesTheToken(t *testing.T) {
	t.Parallel()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "9999999999")
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusForbidden)
		}
		io.WriteString(w, `{}`)
	}))
	t.Cleanup(up.Close)
	srv := &Server{Config: &config.Config{APIURL: up.URL}, Token: testToken}
	client := anonServer(t, srv)
	resp, err := client.Get("http://api.github.com/users/octocat")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(body), "without a token is used up") {
		t.Errorf("%d %s", resp.StatusCode, body)
	}
	if srv.rateLow() {
		t.Error("an anonymous answer lowered the token's rate")
	}
}
