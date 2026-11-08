package proxy

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/peer"
)

const testToken = "ghp_testtoken"

// fakeGitHub serves smart HTTP with real git http-backend over bare repos in
// root, and the one API call the broker makes, after checking the token.
func fakeGitHub(t *testing.T, root string) *httptest.Server {
	t.Helper()
	gitExec, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skip("no git")
	}
	backend := &cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(gitExec)), "git-http-backend"),
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=agent"},
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testToken))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/repos/") {
			if r.Header.Get("Authorization") != "token "+testToken {
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, `{"default_branch":"main"}`)
			return
		}
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(401)
			return
		}
		backend.ServeHTTP(w, r)
	}))
}

func git(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestGitThroughBroker(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	tmp, err := os.MkdirTemp("/tmp", "hpgit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	// A bare repo on the fake GitHub with main and a colleague's branch.
	root := filepath.Join(tmp, "gh")
	bare := filepath.Join(root, "acme", "widgets.git")
	seed := filepath.Join(tmp, "seed")
	for _, args := range [][]string{
		{"init", "-q", "--bare", "-b", "main", bare},
		{"init", "-q", "-b", "main", seed},
	} {
		if out, err := git(t, tmp, nil, args...); err != nil {
			t.Fatal(out)
		}
	}
	plain := []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x"}
	for _, args := range [][]string{
		{"commit", "-q", "--allow-empty", "-m", "seed"},
		{"push", "-q", bare, "main", "main:colleague"},
	} {
		if out, err := git(t, seed, plain, args...); err != nil {
			t.Fatal(out)
		}
	}
	os.WriteFile(filepath.Join(bare, "config"), []byte("[core]\n\tbare = true\n[http]\n\treceivepack = true\n"), 0o644)
	// acme/site is the same repo, with push.default allowed.
	site := filepath.Join(root, "acme", "site.git")
	if out, err := git(t, tmp, plain, "clone", "-q", "--bare", bare, site); err != nil {
		t.Fatal(out)
	}
	os.WriteFile(filepath.Join(site, "config"), []byte("[core]\n\tbare = true\n[http]\n\treceivepack = true\n"), 0o644)

	up := fakeGitHub(t, root)
	defer up.Close()

	sock := filepath.Join(tmp, "git.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Token:             &config.Token{Secret: "file:/x", Source: "pat"},
		Repos:             []config.Repo{{Match: "acme/widgets"}, {Match: "acme/site", Allow: []config.Grant{config.Grant(op.PushDefault)}}},
		ProtectedBranches: []string{"main", "release/*"},
		APIURL:            up.URL + "/api",
		GitURL:            up.URL,
	}
	srv := &Server{
		Config:    cfg,
		Token:     testToken,
		Ledger:    OpenLedger(filepath.Join(tmp, "ledger.jsonl")),
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
	}
	go srv.ServeGit(ln)
	defer ln.Close()

	// The client side: what hallpass install writes, and no credentials.
	gc := filepath.Join(tmp, "gitconfig")
	os.WriteFile(gc, []byte(`[url "http://github.com/"]
	insteadOf = https://github.com/
	insteadOf = git@github.com:
[http "http://github.com/"]
	proxy = socks5h://localhost`+sock+`
	followRedirects = false
[credential]
	helper =
`), 0o644)
	env := []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + gc, "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@x", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@x"}

	work := filepath.Join(tmp, "work")
	if out, err := git(t, tmp, env, "clone", "-q", "git@github.com:acme/widgets.git", work); err != nil {
		t.Fatalf("clone: %s", out)
	}
	git(t, work, env, "commit", "-q", "--allow-empty", "-m", "agent work")

	ok := func(args ...string) {
		t.Helper()
		if out, err := git(t, work, env, args...); err != nil {
			t.Errorf("git %v failed: %s", args, out)
		}
	}
	refused := func(why string, args ...string) {
		t.Helper()
		out, err := git(t, work, env, args...)
		if err == nil || !strings.Contains(out, "hallpass: "+why) {
			t.Errorf("git %v: want refusal %q, got err=%v:\n%s", args, why, err, out)
		}
	}
	ok("push", "-q", "origin", "HEAD:agent/fix")
	ok("commit", "-q", "--amend", "--allow-empty", "-m", "agent work, amended")
	ok("push", "-q", "--force", "origin", "HEAD:agent/fix")
	// Refused pushes change nothing on either side, so they can run at once,
	// alongside the allowlist check.
	var wg sync.WaitGroup
	for _, c := range []struct {
		why  string
		args []string
	}{
		{"main is the default branch", []string{"push", "origin", "HEAD:main"}},
		{"agents can only update branches they created", []string{"push", "--force", "origin", "HEAD:colleague"}},
		{"agents can't push tags", []string{"push", "origin", "HEAD:refs/tags/v1"}},
		{"release/1 is protected", []string{"push", "origin", "HEAD:release/1"}},
		{"agents can only delete branches they created", []string{"push", "origin", ":colleague"}},
	} {
		wg.Go(func() { refused(c.why, c.args...) })
	}
	// A repo outside the allowlist.
	wg.Go(func() {
		if out, err := git(t, tmp, env, "ls-remote", "https://github.com/acme/secret"); err == nil || !strings.Contains(out, "isn't in hallpass's allowlist") {
			t.Errorf("unlisted repo: %v\n%s", err, out)
		}
	})
	wg.Wait()
	ok("push", "-q", "origin", ":agent/fix")

	// GitHub's side: main and the colleague's branch are untouched.
	out, _ := git(t, bare, plain, "for-each-ref", "--format=%(refname)")
	if strings.TrimSpace(out) != "refs/heads/colleague\nrefs/heads/main" {
		t.Errorf("refs on GitHub:\n%s", out)
	}

	// With push.default, main takes the push even though protected_branches
	// names it, and still can't be deleted.
	siteURL := "https://github.com/acme/site"
	ok("push", "-q", siteURL, "HEAD:main")
	refused("agents can't delete the default branch", "push", siteURL, ":main")
	head, _ := git(t, work, env, "rev-parse", "HEAD")
	if got, _ := git(t, site, plain, "rev-parse", "main"); got != head {
		t.Errorf("main on GitHub is %s, want %s", got, head)
	}

	// A broker that isn't there.
	ln.Close()
	if out, err := git(t, work, env, "fetch"); err == nil {
		t.Errorf("fetch with the broker down succeeded:\n%s", out)
	}
	_ = github.Repo{}
}
