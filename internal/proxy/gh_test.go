package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/vektah/gqlparser/v2"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/peer"
	"github.com/mbriggs/hallpass/internal/policy"
)

func TestResolveQueryMatchesSchema(t *testing.T) {
	s, err := policy.Schema()
	if err != nil {
		t.Fatal(err)
	}
	if _, errs := gqlparser.LoadQuery(s, resolveQuery); len(errs) > 0 {
		t.Fatal(errs)
	}
}

// fakeAPI answers the GraphQL and REST calls gh and the broker make, and
// records what reached it.
type fakeAPI struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "token "+testToken {
		w.WriteHeader(401)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	q := string(body)
	switch {
	case r.URL.Path == "/user":
		io.WriteString(w, `{"login":"mbriggs"}`)
	case strings.Contains(q, "nodes(ids"):
		io.WriteString(w, `{"data":{"nodes":[{"__typename":"PullRequest","repository":{"nameWithOwner":"acme/widgets"},"viewerDidAuthor":false}]}}`)
	case strings.Contains(q, "addComment"):
		io.WriteString(w, `{"data":{"addComment":{"commentEdge":{"node":{"url":"https://github.com/acme/widgets/pull/1#c1"}}}}}`)
	case strings.Contains(q, "PullRequestByNumber"):
		io.WriteString(w, `{"data":{"repository":{"pullRequest":{"id":"PR_1","number":1,"url":"https://github.com/acme/widgets/pull/1","title":"t","state":"OPEN","headRefName":"x","headRepositoryOwner":{"id":"U","login":"mbriggs"},"headRepository":{"id":"R","name":"widgets","nameWithOwner":"acme/widgets"},"isCrossRepository":false,"mergeStateStatus":"CLEAN","commits":{"nodes":[{"commit":{"oid":"abc"}}]},"baseRefName":"main"}}}}`)
	case strings.HasPrefix(r.URL.Path, "/repos/acme/widgets"):
		io.WriteString(w, `{"full_name":"acme/widgets"}`)
	default:
		io.WriteString(w, `{"data":{}}`)
	}
}

func TestGHThroughBroker(t *testing.T) {
	t.Parallel()
	ghBin, err := exec.LookPath("gh")
	if err != nil {
		t.Skip("no gh")
	}
	tmp, err := os.MkdirTemp("/tmp", "hpgh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	// broker starts a broker with repos in its allowlist, in front of its
	// own fake GitHub, and returns a way to run gh through it.
	broker := func(name string, repos ...config.Repo) (*fakeAPI, func(...string) (string, error)) {
		api := &fakeAPI{}
		up := httptest.NewServer(api)
		t.Cleanup(up.Close)
		sock := filepath.Join(tmp, name+".sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		srv := &Server{
			Config:    &config.Config{Token: &config.Token{Login: "mbriggs"}, Repos: repos, APIURL: up.URL},
			Token:     testToken,
			Ledger:    OpenLedger(""),
			Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
			Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
		}
		go srv.ServeGH(ln)

		cfgDir := filepath.Join(tmp, name)
		os.MkdirAll(cfgDir, 0o755)
		os.WriteFile(filepath.Join(cfgDir, "config.yml"), []byte("version: \"1\"\nprompt: disabled\ntelemetry: disabled\nhttp_unix_socket: "+sock+"\n"), 0o644)
		os.WriteFile(filepath.Join(cfgDir, "hosts.yml"), []byte("github.com:\n    oauth_token: placeholder\n    user: hallpass\n    git_protocol: https\n"), 0o644)
		return api, func(args ...string) (string, error) {
			cmd := exec.Command(ghBin, args...)
			cmd.Dir = tmp
			cmd.Env = append(os.Environ(), "GH_CONFIG_DIR="+cfgDir, "GH_TOKEN=", "GITHUB_TOKEN=", "GH_NO_UPDATE_NOTIFIER=1", "GH_PROMPT_DISABLED=1", "NO_COLOR=1")
			out, err := cmd.CombinedOutput()
			return string(out), err
		}
	}
	api, run := broker("gh", config.Repo{Match: "acme/widgets"})
	mergeAPI, runMerge := broker("merge", config.Repo{Match: "acme/widgets", Allow: []op.Op{op.PRMerge}})

	// Each call is independent, so they run at once.
	var wg sync.WaitGroup
	wg.Go(func() {
		if out, err := run("api", "repos/acme/widgets", "--jq", ".full_name"); err != nil || strings.TrimSpace(out) != "acme/widgets" {
			t.Errorf("gh api: %v\n%s", err, out)
		}
	})
	wg.Go(func() {
		if out, err := run("pr", "comment", "1", "-R", "acme/widgets", "-b", "looks fine"); err != nil || !strings.Contains(out, "pull/1#c1") {
			t.Errorf("gh pr comment: %v\n%s", err, out)
		}
	})
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"pr", "merge", "1", "-R", "acme/widgets", "--squash"}, "hallpass: agents may not merge PRs or add them to the merge queue in acme/widgets. To allow it: sudo /opt/hallpass/bin/hallpass policy allow pr.merge --repo acme/widgets"},
		{[]string{"pr", "review", "1", "-R", "acme/widgets", "--approve"}, "hallpass: agents may not approve PRs in acme/widgets"},
		{[]string{"pr", "comment", "1", "-R", "acme/widgets", "-b", "/merge"}, "bots act on lines like it"},
		{[]string{"api", "repos/acme/secret"}, "isn't in hallpass's allowlist"},
		{[]string{"api", "-X", "PUT", "repos/acme/widgets/pulls/1/merge"}, "hallpass: agents may not merge PRs"},
		{[]string{"api", "-X", "DELETE", "repos/acme/widgets/git/refs/heads/main"}, "hallpass doesn't allow DELETE"},
	} {
		wg.Go(func() {
			out, err := run(c.args...)
			if err == nil || !strings.Contains(out, c.want) {
				t.Errorf("gh %v: want %q, got err=%v:\n%s", c.args, c.want, err, out)
			}
		})
	}
	// With pr.merge allowed, the same merge reaches GitHub, and approvals
	// stay refused.
	wg.Go(func() { runMerge("pr", "merge", "1", "-R", "acme/widgets", "--squash") })
	wg.Go(func() {
		if out, err := runMerge("pr", "review", "1", "-R", "acme/widgets", "--approve"); err == nil || !strings.Contains(out, "may not approve PRs") {
			t.Errorf("approval with only pr.merge allowed: %v\n%s", err, out)
		}
	})
	wg.Wait()
	mergeAPI.mu.Lock()
	merged := slices.ContainsFunc(mergeAPI.seen, func(s string) bool { return strings.Contains(s, "mergePullRequest(") })
	mergeAPI.mu.Unlock()
	if !merged {
		t.Error("with pr.merge allowed, gh pr merge didn't reach GitHub")
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	for _, s := range api.seen {
		if strings.Contains(s, "mergePullRequest") || strings.Contains(s, "APPROVE") || strings.Contains(s, "acme/secret") || strings.Contains(s, "/merge") {
			t.Errorf("refused request reached GitHub: %.200s", s)
		}
	}
	_ = json.Valid
}
