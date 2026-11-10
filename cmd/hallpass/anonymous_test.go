package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mbriggs/hallpass/internal/broker"
	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/peer"
	"github.com/mbriggs/hallpass/internal/sshgate"
)

// A fetch of a repo outside the allowlist goes to GitHub's smart HTTP with
// no credential, through real git and git http-backend. The fake answers
// as GitHub does without a token: octo/public is public, acme/private is
// a 401, octo/old redirects to octo/public, octo/away redirects off the
// host, and octo/busy is rate limited.
func TestGitFetchesWithoutCredentialOutsideAllowlist(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	tmp, err := os.MkdirTemp("/tmp", "hpanon")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	plain := []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x"}
	gitIn := func(dir string, env []string, args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	must := func(dir string, args ...string) {
		t.Helper()
		if out, err := gitIn(dir, plain, args...); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	root := filepath.Join(tmp, "gh")
	seed := func(repo, file, text string) string {
		bare := filepath.Join(root, repo+".git")
		work := filepath.Join(tmp, "seed-"+strings.ReplaceAll(repo, "/", "-"))
		must(tmp, "init", "-q", "--bare", "-b", "main", bare)
		must(bare, "config", "uploadpack.allowFilter", "true")
		must(tmp, "init", "-q", "-b", "main", work)
		os.WriteFile(filepath.Join(work, file), []byte(text), 0o644)
		must(work, "add", "-A")
		must(work, "commit", "-q", "-m", "one")
		os.WriteFile(filepath.Join(work, "second"), []byte("two\n"), 0o644)
		must(work, "add", "-A")
		must(work, "commit", "-q", "-m", "two")
		must(work, "push", "-q", bare, "main")
		return work
	}
	publicSeed := seed("octo/public", "README", "public\n")
	seed("acme/private", "SECRET", "private-marker\n")
	seed("acme/widgets", "README", "widgets\n")

	// GitHub's smart HTTP, as an anonymous client sees it.
	var mu sync.Mutex
	var hits []string
	backend := &cgi.Handler{Path: gitBin, Args: []string{"http-backend"}, Env: append(slices.Clone(plain), "GIT_PROJECT_ROOT="+root, "GIT_HTTP_EXPORT_ALL=1")}
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization")+" proto="+r.Header.Get("Git-Protocol"))
		mu.Unlock()
		switch {
		case r.Header.Get("Authorization") != "":
			http.Error(w, "credential sent", http.StatusBadRequest)
		case strings.HasPrefix(r.URL.Path, "/octo/public.git/"):
			// The broker streams each command as chunks, which CGI can't
			// take, so the fake reads it whole first.
			body, _ := io.ReadAll(r.Body)
			r.Body, r.ContentLength, r.TransferEncoding = io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil
			backend.ServeHTTP(w, r)
		case r.URL.Path == "/octo/old.git/info/refs":
			http.Redirect(w, r, "/octo/public.git/info/refs?"+r.URL.RawQuery, http.StatusMovedPermanently)
		case r.URL.Path == "/octo/away.git/info/refs":
			http.Redirect(w, r, "http://127.0.0.1:1/octo/public.git/info/refs?"+r.URL.RawQuery, http.StatusMovedPermanently)
		case r.URL.Path == "/octo/busy.git/info/refs":
			http.Error(w, "rate limited", http.StatusTooManyRequests)
		default:
			// GitHub answers a private or missing repo with a 401 asking
			// for credentials.
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			http.Error(w, "", http.StatusUnauthorized)
		}
	}))
	t.Cleanup(gh.Close)
	httpHits := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(hits)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(&key.PublicKey)
	var sshFetches atomic.Int32
	addr, hostKey := fakeGitHubSSH(t, root, pub, func(string, []string) io.Writer {
		sshFetches.Add(1)
		return nil
	})

	// Two gates: one with the default policy, one that denies anonymous.
	logs := new(syncBuffer)
	start := func(dir string, cfg *config.Config) []string {
		os.MkdirAll(dir, 0o700)
		t.Setenv("HALLPASS_RUN_DIR", dir)
		ln, err := broker.Listen("ssh", config.Socket("ssh"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		gate := &sshgate.Server{
			Config:    cfg,
			Signer:    key,
			Ledger:    sshgate.OpenLedger(""),
			Log:       slog.New(slog.NewTextHandler(logs, nil)),
			Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
			Addrs:     []string{addr},
			HostKeys:  []string{hostKey},
			GitURL:    gh.URL,
		}
		go gate.Serve(ln)
		self, _ := os.Executable()
		gc := filepath.Join(dir, "gitconfig")
		os.WriteFile(gc, []byte(`[url "ssh://git@github.com/"]
	insteadOf = https://github.com/
[core]
	sshCommand = `+self+` ssh
[ssh]
	variant = ssh
`), 0o644)
		return slices.Concat(plain[2:], []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + gc, "HALLPASS_AS_MAIN=1", "HALLPASS_RUN_DIR=" + dir})
	}
	allowlist := []config.Repo{{Match: "acme/widgets"}}
	env := start(filepath.Join(tmp, "run"), &config.Config{SSH: &config.Key{}, Repos: allowlist})
	denied := start(filepath.Join(tmp, "run-denied"), &config.Config{SSH: &config.Key{}, Repos: allowlist, Deny: []config.Grant{config.Grant(op.Anonymous)}})

	ok := func(env []string, dir string, args ...string) string {
		t.Helper()
		out, err := gitIn(dir, env, args...)
		if err != nil {
			t.Errorf("git %v: %s", args, out)
		}
		return out
	}
	refused := func(env []string, why string, args ...string) string {
		t.Helper()
		out, err := gitIn(tmp, env, args...)
		if err == nil || !strings.Contains(out, why) {
			t.Errorf("git %v: want %q, got err=%v:\n%s", args, why, err, out)
		}
		return out
	}
	allowlistMsg := func(repo string) string {
		return repo + " isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow " + repo
	}

	// A public repo clones, fetches after it changes, and does so without
	// a credential or the SSH key.
	work := filepath.Join(tmp, "public")
	ok(env, tmp, "clone", "-q", "https://github.com/octo/public", work)
	if b, _ := os.ReadFile(filepath.Join(work, "README")); string(b) != "public\n" {
		t.Errorf("clone's README = %q", b)
	}
	os.WriteFile(filepath.Join(publicSeed, "third"), []byte("three\n"), 0o644)
	must(publicSeed, "add", "-A")
	must(publicSeed, "commit", "-q", "-m", "three")
	must(publicSeed, "push", "-q", filepath.Join(root, "octo/public.git"), "main")
	ok(env, work, "commit", "-q", "--allow-empty", "-m", "local")
	ok(env, work, "pull", "-q", "--no-rebase", "--no-edit")
	if _, err := os.Stat(filepath.Join(work, "third")); err != nil {
		t.Errorf("fetch didn't bring the new commit: %v", err)
	}
	ok(env, tmp, "clone", "-q", "--depth", "1", "https://github.com/octo/public", filepath.Join(tmp, "shallow"))
	if out := ok(env, filepath.Join(tmp, "shallow"), "rev-list", "--count", "HEAD"); strings.TrimSpace(out) != "1" {
		t.Errorf("shallow clone has %s commits", strings.TrimSpace(out))
	}
	ok(env, tmp, "clone", "-q", "--filter=blob:none", "https://github.com/octo/public", filepath.Join(tmp, "partial"))
	if sshFetches.Load() != 0 {
		t.Errorf("the gate used the SSH key %d times for a public repo", sshFetches.Load())
	}
	for _, h := range httpHits() {
		if !strings.HasSuffix(h, "auth= proto=version=2") {
			t.Errorf("GitHub got %q", h)
		}
	}
	if !strings.Contains(string(logs.Bytes()), "msg=allowed via=ssh") || !strings.Contains(string(logs.Bytes()), "repo=octo/public op=upload-pack anonymous=true exit=0") {
		t.Errorf("log lacks the anonymous fetch:\n%s", logs.Bytes())
	}

	// A push to it is refused before anything reaches GitHub.
	before := len(httpHits())
	refused(env, allowlistMsg("octo/public"), "-C", work, "push", "https://github.com/octo/public", "HEAD:main")
	if n := len(httpHits()); n != before {
		t.Errorf("a refused push reached GitHub's HTTP: %v", httpHits()[before:])
	}

	// A private repo is refused, and nothing of it reaches git.
	out := refused(env, "Without a token, GitHub answered 401 Unauthorized. "+allowlistMsg("acme/private"), "ls-remote", "https://github.com/acme/private")
	if strings.Contains(out, "refs/heads") {
		t.Errorf("ls-remote of a private repo printed refs:\n%s", out)
	}
	refused(env, "Without a token, GitHub answered 401", "clone", "-q", "https://github.com/acme/private", filepath.Join(tmp, "private"))
	if _, err := os.Stat(filepath.Join(tmp, "private", "SECRET")); err == nil {
		t.Error("the private repo's file reached the clone")
	}

	// A renamed public repo follows GitHub's redirect on the same host;
	// one to another host isn't followed.
	if out := ok(env, tmp, "ls-remote", "https://github.com/octo/old"); !strings.Contains(out, "refs/heads/main") {
		t.Errorf("ls-remote of a renamed repo:\n%s", out)
	}
	if !strings.Contains(string(logs.Bytes()), "repo=octo/old op=upload-pack anonymous=true now=octo/public exit=0") {
		t.Errorf("log lacks the rename:\n%s", logs.Bytes())
	}
	refused(env, "GitHub redirected somewhere hallpass doesn't follow. "+allowlistMsg("octo/away"), "ls-remote", "https://github.com/octo/away")

	refused(env, "GitHub is limiting git without a token from this machine's address (429 Too Many Requests); try again later.", "ls-remote", "https://github.com/octo/busy")
	refused(env, "only over git protocol v2", "-c", "protocol.version=0", "ls-remote", "https://github.com/octo/public")

	// The anonymous operation turns it off.
	before = len(httpHits())
	out = refused(denied, "hallpass: "+allowlistMsg("octo/public"), "ls-remote", "https://github.com/octo/public")
	if strings.Contains(out, "Without a token") || len(httpHits()) != before {
		t.Errorf("with anonymous denied, the gate asked GitHub:\n%s", out)
	}

	// An allowed repo still goes over SSH with the key, on both gates.
	ok(env, tmp, "ls-remote", "https://github.com/acme/widgets")
	ok(denied, tmp, "ls-remote", "https://github.com/acme/widgets")
	if sshFetches.Load() != 2 {
		t.Errorf("allowed repo used SSH %d times, want 2", sshFetches.Load())
	}
	for _, h := range httpHits() {
		if strings.Contains(h, "widgets") {
			t.Errorf("an allowed repo went to HTTP: %s", h)
		}
	}
}
