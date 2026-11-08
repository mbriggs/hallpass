package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
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
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/peer"
	"github.com/mbriggs/hallpass/internal/sshgate"
)

// fakeGitHubSSH runs real git-upload-pack and git-receive-pack over bare
// repos in root, for clients that authenticate with clientKey. hook, if
// set, runs before each command with its service and environment.
func fakeGitHubSSH(t *testing.T, root string, clientKey ssh.PublicKey, hook func(svc string, env []string)) (addr, hostKey string) {
	t.Helper()
	hk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hs, _ := ssh.NewSignerFromSigner(hk)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) != string(clientKey.Marshal()) {
			return nil, io.EOF
		}
		return nil, nil
	}}
	cfg.AddHostKey(hs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSH(c, cfg, root, hook)
		}
	}()
	return ln.Addr().String(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hs.PublicKey())))
}

func serveSSH(c net.Conn, cfg *ssh.ServerConfig, root string, hook func(string, []string)) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			var env []string
			for req := range creqs {
				switch req.Type {
				case "env":
					var kv struct{ K, V string }
					ssh.Unmarshal(req.Payload, &kv)
					env = append(env, kv.K+"="+kv.V)
					req.Reply(true, nil)
				case "exec":
					var cmd struct{ C string }
					ssh.Unmarshal(req.Payload, &cmd)
					req.Reply(true, nil)
					svc, repo, err := sshgate.ParseCommand(cmd.C)
					status := uint32(1)
					if err == nil && hook != nil {
						hook(svc, env)
					}
					if err == nil {
						g := exec.Command("git", strings.TrimPrefix(svc, "git-"), filepath.Join(root, repo.Owner, repo.Name+".git"))
						g.Env = append(os.Environ(), env...)
						g.Stdin, g.Stdout, g.Stderr = ch, ch, ch.Stderr()
						if g.Run() == nil {
							status = 0
						}
					}
					var b [4]byte
					binary.BigEndian.PutUint32(b[:], status)
					ch.SendRequest("exit-status", false, b[:])
					return
				default:
					req.Reply(false, nil)
				}
			}
		}()
	}
}

func TestGitOverSSHThroughBroker(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	tmp, err := os.MkdirTemp("/tmp", "hpssh")
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
	root := filepath.Join(tmp, "gh")
	bare := filepath.Join(root, "acme", "widgets.git")
	seed := filepath.Join(tmp, "seed")
	for _, a := range [][]string{{"init", "-q", "--bare", "-b", "main", bare}, {"init", "-q", "-b", "main", seed}} {
		if out, err := gitIn(tmp, plain, a...); err != nil {
			t.Fatal(out)
		}
	}
	os.MkdirAll(filepath.Join(seed, ".github", "workflows"), 0o755)
	os.WriteFile(filepath.Join(seed, ".github", "workflows", "ci.yml"), []byte("on: push\n"), 0o644)
	for _, a := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "seed"}, {"push", "-q", bare, "main", "main:colleague"}} {
		if out, err := gitIn(seed, plain, a...); err != nil {
			t.Fatal(out)
		}
	}
	// acme/site starts as a copy, and allows push.default.
	site := filepath.Join(root, "acme", "site.git")
	if out, err := gitIn(tmp, plain, "clone", "-q", "--bare", bare, site); err != nil {
		t.Fatal(out)
	}
	// What GitHub allows: blobless fetches of any commit.
	for _, repo := range []string{bare, site} {
		for _, kv := range [][]string{{"uploadpack.allowFilter", "true"}, {"uploadpack.allowAnySHA1InWant", "true"}} {
			gitIn(repo, plain, "config", kv[0], kv[1])
		}
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(&key.PublicKey)
	// flipHead, when set, makes agent/fix the default branch at the
	// broker's blobless fetch, which comes after it reads a push's pack and
	// before it forwards the push.
	var flipHead atomic.Bool
	addr, hostKey := fakeGitHubSSH(t, root, pub, func(svc string, env []string) {
		if svc == "git-upload-pack" && slices.Contains(env, "GIT_PROTOCOL=version=2") && flipHead.CompareAndSwap(true, false) {
			if out, err := exec.Command("git", "-C", bare, "symbolic-ref", "HEAD", "refs/heads/agent/fix").CombinedOutput(); err != nil {
				t.Errorf("symbolic-ref: %s", out)
			}
		}
	})

	t.Setenv("HALLPASS_RUN_DIR", tmp)
	ln, err := broker.Listen("ssh", config.Socket("ssh"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	gate := &sshgate.Server{
		Config: &config.Config{
			SSH:               &config.Key{},
			Repos:             []config.Repo{{Match: "acme/widgets"}, {Match: "acme/site", Allow: []config.Grant{config.Grant(op.PushDefault)}}},
			ProtectedBranches: []string{"main", "release/*"},
		},
		Signer:    key,
		Ledger:    sshgate.OpenLedger(""),
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
		Addr:      addr,
		HostKeys:  []string{hostKey},
	}
	go gate.Serve(ln)

	self, _ := os.Executable()
	gc := filepath.Join(tmp, "gitconfig")
	os.WriteFile(gc, []byte(`[url "ssh://git@github.com/"]
	insteadOf = https://github.com/
[core]
	sshCommand = `+self+` ssh
[ssh]
	variant = ssh
`), 0o644)
	env := append(plain[2:], "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+gc, "HALLPASS_AS_MAIN=1", "HALLPASS_RUN_DIR="+tmp)
	work := filepath.Join(tmp, "work")
	if out, err := gitIn(tmp, env, "clone", "-q", "https://github.com/acme/widgets", work); err != nil {
		t.Fatalf("clone: %s", out)
	}
	gitIn(work, env, "commit", "-q", "--allow-empty", "-m", "agent work")
	ok := func(args ...string) {
		t.Helper()
		if out, err := gitIn(work, env, args...); err != nil {
			t.Errorf("git %v: %s", args, out)
		}
	}
	refused := func(why string, args ...string) {
		t.Helper()
		out, err := gitIn(work, env, args...)
		if err == nil || !strings.Contains(out, why) {
			t.Errorf("git %v: want %q, got err=%v:\n%s", args, why, err, out)
		}
	}
	ok("fetch", "-q")
	ok("push", "-q", "origin", "HEAD:agent/fix")
	ok("commit", "-q", "--amend", "--allow-empty", "-m", "amended")
	ok("push", "-q", "--force", "origin", "HEAD:agent/fix")
	// Refusals change nothing on either side, so they run at once.
	refusedAll := func(cases ...[]string) {
		t.Helper()
		var wg sync.WaitGroup
		for _, c := range cases {
			wg.Go(func() { refused(c[0], c[1:]...) })
		}
		wg.Wait()
	}
	refusedAll(
		[]string{"main is the default branch", "push", "origin", "HEAD:main"},
		[]string{"agents can only update branches they created", "push", "--force", "origin", "HEAD:colleague"},
		[]string{"agents can't push tags", "push", "origin", "HEAD:refs/tags/v1"},
		[]string{"isn't in hallpass's allowlist", "ls-remote", "https://github.com/acme/secret"},
		// A delete sends no pack, so the refusal can't wait for one.
		[]string{"agents can only delete branches they created", "push", "origin", ":colleague"},
	)

	// A workflow change, buried under a clean commit, never reaches GitHub.
	os.WriteFile(filepath.Join(work, ".github", "workflows", "ci.yml"), []byte("on: push\njobs: {steal: {}}\n"), 0o644)
	gitIn(work, env, "commit", "-q", "-am", "edit workflow")
	os.WriteFile(filepath.Join(work, "README"), []byte("hi\n"), 0o644)
	gitIn(work, env, "add", "README")
	gitIn(work, env, "commit", "-q", "-m", "innocent")
	refusedAll(
		[]string{"agents can't change .github/workflows", "push", "origin", "HEAD:agent/fix"},
		[]string{"agents can't change .github/workflows", "push", "origin", "HEAD:agent/new"},
	)
	// Code changes on top of the last pushed commit still go through.
	gitIn(work, env, "reset", "-q", "--hard", "origin/agent/fix")
	os.WriteFile(filepath.Join(work, "README"), []byte("code\n"), 0o644)
	gitIn(work, env, "add", "README")
	gitIn(work, env, "commit", "-q", "-m", "code")
	ok("push", "-q", "origin", "HEAD:agent/fix")

	// A fork PR's head is already on GitHub. Pointing a branch at it would run
	// its workflows with the repo's secrets, and the push carries no objects.
	os.WriteFile(filepath.Join(seed, ".github", "workflows", "ci.yml"), []byte("on: push\njobs: {fork: {}}\n"), 0o644)
	gitIn(seed, plain, "commit", "-q", "-am", "fork PR")
	gitIn(seed, plain, "push", "-q", bare, "HEAD:refs/pull/1/head")
	gitIn(work, env, "fetch", "-q", "origin", "refs/pull/1/head")
	refused("agents can't change .github/workflows", "push", "origin", "FETCH_HEAD:refs/heads/agent/fork")

	out, _ := gitIn(bare, plain, "for-each-ref", "--format=%(refname)", "refs/heads")
	if strings.TrimSpace(out) != "refs/heads/agent/fix\nrefs/heads/colleague\nrefs/heads/main" {
		t.Errorf("refs on GitHub:\n%s", out)
	}

	// With push.default, acme/site's main takes the push even though
	// protected_branches names it, and still can't be deleted.
	siteURL := "https://github.com/acme/site"
	gitIn(work, env, "reset", "-q", "--hard", "origin/agent/fix")
	ok("push", "-q", siteURL, "HEAD:main")
	refused("agents can't delete the default branch", "push", siteURL, ":main")
	refused("release/1 is protected", "push", siteURL, "HEAD:release/1")
	head, _ := gitIn(work, env, "rev-parse", "HEAD")
	if got, _ := gitIn(site, plain, "rev-parse", "main"); got != head {
		t.Errorf("acme/site main is %s, want %s", got, head)
	}

	// The ledger holds the commit agents last pushed, not just the name. A
	// branch the user deleted and made again under the same name is theirs,
	// and so is one they pushed to.
	userTip := func(msg, ref string) string {
		t.Helper()
		gitIn(seed, plain, "commit", "-q", "--allow-empty", "-m", msg)
		if out, err := gitIn(seed, plain, "push", "-q", "--force", bare, "HEAD:"+ref); err != nil {
			t.Fatal(out)
		}
		out, _ := gitIn(seed, plain, "rev-parse", "HEAD")
		return strings.TrimSpace(out)
	}
	gitIn(work, env, "reset", "-q", "--hard", "origin/agent/fix")
	ok("push", "-q", "origin", "HEAD:agent/reuse", "HEAD:agent/gone")
	gitIn(seed, plain, "push", "-q", bare, ":agent/reuse")
	reused := userTip("user's own reuse", "agent/reuse")
	ok("push", "-q", "origin", ":agent/gone")
	gone := userTip("user's own gone", "agent/gone")
	pushedTo := userTip("user adds to the agent's branch", "agent/fix")
	ok("fetch", "-q")
	gitIn(work, env, "commit", "-q", "--allow-empty", "-m", "agent again")
	refusedAll(
		[]string{"agent/reuse has changed since an agent last pushed it", "push", "--force", "origin", "HEAD:agent/reuse"},
		[]string{"agents can only delete branches they created", "push", "origin", ":agent/gone"},
		[]string{"ledger add acme/widgets agent/fix " + pushedTo, "push", "--force", "origin", "HEAD:agent/fix"},
	)
	for ref, want := range map[string]string{"agent/reuse": reused, "agent/gone": gone, "agent/fix": pushedTo} {
		if got, _ := gitIn(bare, plain, "rev-parse", ref); strings.TrimSpace(got) != want {
			t.Errorf("%s on GitHub is %s, want the user's %s", ref, got, want)
		}
	}
	// ledger add hands the branch over as it is, and agents go on from there.
	if err := gate.Ledger.Record(github.Repo{Owner: "acme", Name: "widgets"}, "agent/fix", pushedTo, "added by hand"); err != nil {
		t.Fatal(err)
	}
	ok("push", "-q", "--force", "origin", "HEAD:agent/fix")
	ok("push", "-q", "--force", "origin", "HEAD~1:agent/fix")

	// The user makes agent/fix the default branch while an agent's push to
	// it is in flight. The broker checks the default again after the pack.
	before, _ := gitIn(bare, plain, "rev-parse", "agent/fix")
	flipHead.Store(true)
	refused("agent/fix is the default branch", "push", "origin", "HEAD:agent/fix")
	if flipHead.Load() {
		t.Error("the push never reached the broker's blobless fetch")
	}
	if after, _ := gitIn(bare, plain, "rev-parse", "agent/fix"); after != before {
		t.Errorf("agent/fix moved from %s to %s", before, after)
	}
}
