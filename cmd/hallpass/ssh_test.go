package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
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
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mbriggs/hallpass/internal/audit"
	"github.com/mbriggs/hallpass/internal/broker"
	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/peer"
	"github.com/mbriggs/hallpass/internal/sshgate"
)

// fakeGitHubSSH runs real git-upload-pack and git-receive-pack over bare
// repos in root, for clients that authenticate with clientKey. hook, if
// set, runs before each command with its service and environment, and may
// return a writer that gets a copy of the command's stdin.
func fakeGitHubSSH(t *testing.T, root string, clientKey ssh.PublicKey, hook func(svc string, env []string) io.Writer) (addr, hostKey string) {
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

func serveSSH(c net.Conn, cfg *ssh.ServerConfig, root string, hook func(string, []string) io.Writer) {
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
					var capture io.Writer
					if err == nil && hook != nil {
						capture = hook(svc, env)
					}
					if err == nil {
						g := exec.Command("git", strings.TrimPrefix(svc, "git-"), filepath.Join(root, repo.Owner, repo.Name+".git"))
						g.Env = append(os.Environ(), env...)
						g.Stdout, g.Stderr = ch, ch.Stderr()
						var src io.Reader = ch
						if capture != nil {
							src = io.TeeReader(ch, capture)
						}
						// GitHub ends the channel when git exits, even if the
						// client never sends anything, as when the repo is
						// missing. So copy stdin where Wait doesn't wait on it.
						stdin, _ := g.StdinPipe()
						go func() {
							_, _ = io.Copy(stdin, src)
							stdin.Close()
						}()
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
	// flipHead, when set, makes the branch it names the default branch at
	// the broker's blobless fetch, which comes after it reads a push's pack
	// and before it forwards the push.
	var flipHead atomic.Pointer[string]
	// upstream, when set, gets a copy of what the next receive-pack reads.
	var upstream atomic.Pointer[syncBuffer]
	addr, hostKey := fakeGitHubSSH(t, root, pub, func(svc string, env []string) io.Writer {
		if svc == "git-receive-pack" {
			if b := upstream.Swap(nil); b != nil {
				return b
			}
		}
		if svc != "git-upload-pack" || !slices.Contains(env, "GIT_PROTOCOL=version=2") {
			return nil
		}
		if to := flipHead.Swap(nil); to != nil {
			if out, err := exec.Command("git", "-C", bare, "symbolic-ref", "HEAD", "refs/heads/"+*to).CombinedOutput(); err != nil {
				t.Errorf("symbolic-ref: %s", out)
			}
		}
		return nil
	})

	t.Setenv("HALLPASS_RUN_DIR", tmp)
	ln, err := broker.Listen("ssh", config.Socket("ssh"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	spoolDir := filepath.Join(tmp, "spool")
	spool, err := sshgate.OpenSpool(spoolDir, sshgate.MaxSpool)
	if err != nil {
		t.Fatal(err)
	}
	gateConfig := &config.Config{
		SSH: &config.Key{},
		Repos: []config.Repo{{Match: "acme/widgets"}, {Match: "acme/site", Allow: []config.Grant{config.Grant(op.PushDefault)}},
			// acme/missing is allowed but has no repo, so GitHub sends no ref list.
			{Match: "acme/missing"}},
		ProtectedBranches: []string{"main", "release/*"},
	}
	// brokerLog is the gate's log, as the broker writes it.
	brokerLog := new(syncBuffer)
	// logAfter waits for the line with msg=want that the gate logs after
	// byte mark, which can come just after git exits, and returns the log
	// from mark on.
	logAfter := func(mark int, want string) string {
		t.Helper()
		for range 100 {
			if l := string(brokerLog.Bytes()[mark:]); strings.Contains(l, want) {
				return l
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("the gate didn't log %s; it logged:\n%s", want, brokerLog.Bytes()[mark:])
		return ""
	}
	gate := &sshgate.Server{
		Config:    gateConfig,
		Signer:    key,
		Ledger:    sshgate.OpenLedger(""),
		Spool:     spool,
		Log:       slog.New(slog.NewTextHandler(brokerLog, nil)),
		Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
		Addrs:     []string{addr},
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
	env := slices.Concat(plain[2:], []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + gc, "HALLPASS_AS_MAIN=1", "HALLPASS_RUN_DIR=" + tmp})
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
	// git asks for protocol v2, and the gate passes the request on.
	if out, _ := gitIn(work, append(env, "GIT_TRACE_PACKET=1"), "ls-remote", "origin", "main"); !strings.Contains(out, "< version 2") {
		t.Errorf("ls-remote didn't speak protocol v2:\n%s", out)
	}
	// The pack waits on disk while the broker checks it, then reaches
	// GitHub byte for byte as git sent it. The broker writes the commands
	// out again, so compare from the pack on.
	sent := filepath.Join(tmp, "sent")
	got := new(syncBuffer)
	upstream.Store(got)
	ok("-c", "core.sshCommand=tee "+sent+" | "+self+" ssh", "push", "-q", "origin", "HEAD:agent/fix")
	packOf := func(b []byte) []byte { return b[max(bytes.Index(b, []byte("PACK")), 0):] }
	if want, _ := os.ReadFile(sent); !bytes.HasPrefix(packOf(want), []byte("PACK")) || !bytes.Equal(packOf(got.Bytes()), packOf(want)) {
		t.Errorf("GitHub got a %d-byte pack, git sent %d bytes", len(packOf(got.Bytes())), len(packOf(want)))
	}
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
	// None of a refused pack reaches GitHub.
	got = new(syncBuffer)
	upstream.Store(got)
	refused("agents can't change .github/workflows", "push", "origin", "HEAD:agent/new")
	if bytes.Contains(got.Bytes(), []byte("PACK")) {
		t.Errorf("GitHub got a refused pack: %q", got.Bytes())
	}
	upstream.Store(nil)
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
	// The workflow check needs blobless shallow fetches, and says so when
	// GitHub doesn't offer them.
	gitIn(site, plain, "config", "uploadpack.allowFilter", "false")
	refused("GitHub's fetch doesn't offer filter and shallow", "push", siteURL, "HEAD:main")
	gitIn(site, plain, "config", "uploadpack.allowFilter", "true")
	ok("push", "-q", siteURL, "HEAD:main")
	refused("agents can't delete the default branch", "push", siteURL, ":main")
	refused("release/1 is protected", "push", siteURL, "HEAD:release/1")
	head, _ := gitIn(work, env, "rev-parse", "HEAD")
	if got, _ := gitIn(site, plain, "rev-parse", "main"); got != head {
		t.Errorf("acme/site main is %s, want %s", got, head)
	}
	// push.default governs the default branch, so the ledger leaves it out.
	if tip := gate.Ledger.Tip(github.Repo{Owner: "acme", Name: "site"}, "main"); tip != "" {
		t.Errorf("the ledger recorded acme/site main at %s", tip)
	}

	// The ledger records only the refs GitHub accepted, and the log says
	// which it rejected and why, whether it rejected some refs or all.
	os.WriteFile(filepath.Join(bare, "hooks", "update"), []byte("#!/bin/sh\ntest \"$1\" != refs/heads/agent/declined\n"), 0o755)
	mark := len(brokerLog.Bytes())
	refused("hook declined", "push", "origin", "HEAD:agent/taken", "HEAD:agent/declined")
	partial := logAfter(mark, "msg=allowed")
	mark = len(brokerLog.Bytes())
	refused("hook declined", "push", "origin", "HEAD:agent/declined")
	whole := logAfter(mark, "msg=allowed")
	os.Remove(filepath.Join(bare, "hooks", "update"))
	widgets := github.Repo{Owner: "acme", Name: "widgets"}
	if gate.Ledger.Tip(widgets, "agent/taken") == "" || gate.Ledger.Tip(widgets, "agent/declined") != "" {
		t.Errorf("ledger after a half-accepted push: %v", gate.Ledger.Branches(widgets))
	}
	declined := `rejected="[{\"ref\":\"refs/heads/agent/declined\",\"reason\":\"hook declined\"}]"`
	for _, c := range []struct{ name, log, line, shown string }{
		{"partly rejected", partial, "level=WARN msg=pushed ",
			"pushed   ssh  acme/widgets  push refs/heads/agent/taken; GitHub rejected refs/heads/agent/declined: hook declined -> exit 0"},
		{"wholly rejected", whole, "level=WARN msg=rejected ",
			"rejected  ssh  acme/widgets  push, GitHub rejected refs/heads/agent/declined: hook declined -> exit 0"},
	} {
		if !strings.Contains(c.log, c.line) || !strings.Contains(c.log, declined) {
			t.Errorf("%s push logged:\n%s", c.name, c.log)
		}
		var out bytes.Buffer
		if err := printLog(&out, strings.NewReader(c.log), audit.Filter{}, logOpts{view: utc}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), c.shown) {
			t.Errorf("hallpass log shows the %s push as\n%s\nwant\n%s", c.name, out.String(), c.shown)
		}
		if strings.Count(out.String(), "\n") != 1 {
			t.Errorf("the %s push takes more than one line:\n%s", c.name, out.String())
		}
	}

	// A push that fails before the checks, because GitHub sent no ref list
	// or no default branch, still leaves a line.
	mark = len(brokerLog.Bytes())
	refused("couldn't read GitHub's ref list", "push", "https://github.com/acme/missing", "HEAD:agent/x")
	if l := logAfter(mark, "msg=failed"); !strings.Contains(l, `level=WARN msg=failed via=ssh`) ||
		!strings.Contains(l, `repo=acme/missing op=receive-pack reason="couldn't read GitHub's ref list: EOF"`) {
		t.Errorf("a push with no ref list logged:\n%s", l)
	}
	gitIn(bare, plain, "symbolic-ref", "HEAD", "refs/heads/nowhere")
	mark = len(brokerLog.Bytes())
	refused("couldn't check the default branch", "push", "origin", "HEAD:agent/x")
	gitIn(bare, plain, "symbolic-ref", "HEAD", "refs/heads/main")
	if l := logAfter(mark, "msg=failed"); !strings.Contains(l, `repo=acme/widgets op=receive-pack reason="couldn't check the default branch: `) {
		t.Errorf("a push with no default branch logged:\n%s", l)
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
	flipHead.Store(new("agent/fix"))
	refused("agent/fix is the default branch", "push", "origin", "HEAD:agent/fix")
	if flipHead.Load() != nil {
		t.Error("the push never reached the broker's blobless fetch")
	}
	if after, _ := gitIn(bare, plain, "rev-parse", "agent/fix"); after != before {
		t.Errorf("agent/fix moved from %s to %s", before, after)
	}
	// A new default that the push doesn't touch lets it through.
	flipHead.Store(new("colleague"))
	ok("push", "-q", "origin", "HEAD:agent/moved")
	head, _ = gitIn(work, env, "rev-parse", "HEAD")
	if got, _ := gitIn(bare, plain, "rev-parse", "agent/moved"); got != head {
		t.Errorf("agent/moved on GitHub is %s, want %s", got, head)
	}
	if left, _ := os.ReadDir(spoolDir); len(left) > 0 {
		t.Errorf("the spool kept %d files", len(left))
	}

	// A second gate whose spool holds 16 KB in all.
	tmp2, err := os.MkdirTemp("/tmp", "hpssh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp2) })
	small, err := sshgate.OpenSpool(filepath.Join(tmp2, "spool"), 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	ln2, err := broker.Listen("ssh", filepath.Join(tmp2, "ssh.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	gate2 := &sshgate.Server{
		Config:    gateConfig,
		Signer:    key,
		Ledger:    gate.Ledger,
		Spool:     small,
		Log:       gate.Log,
		Permitted: gate.Permitted,
		Addrs:     gate.Addrs,
		HostKeys:  gate.HostKeys,
	}
	go gate2.Serve(ln2)
	env = append(env, "HALLPASS_RUN_DIR="+tmp2)

	// A push past the spool's room is refused before any of it reaches
	// GitHub.
	noise := make([]byte, 64<<10)
	rand.Read(noise)
	os.WriteFile(filepath.Join(work, "noise"), noise, 0o644)
	gitIn(work, env, "add", "noise")
	gitIn(work, env, "commit", "-q", "-m", "noise")
	refused("the broker is holding too many pushes", "push", "origin", "HEAD:agent/big")
	if out, err := gitIn(bare, plain, "rev-parse", "--verify", "-q", "agent/big"); err == nil {
		t.Errorf("agent/big reached GitHub at %s", out)
	}

	// A client that sends most of the room and goes away gives it back.
	c, err := net.Dial("unix", filepath.Join(tmp2, "ssh.sock"))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte(`{"service":"git-receive-pack","repo":"acme/widgets"}` + "\n"))
	if _, _, err := sshgate.ReadFrame(c); err != nil {
		t.Fatal(err)
	}
	cmd := strings.Repeat("0", 40) + " " + strings.Repeat("1", 40) + " refs/heads/agent/gone-away\x00report-status\n"
	c.Write(fmt.Appendf(nil, "%04x%s0000PACK", len(cmd)+4, cmd))
	c.Write(make([]byte, 16000))
	c.Close()
	gitIn(work, env, "reset", "-q", "--hard", "HEAD~1")
	gitIn(work, env, "commit", "-q", "--allow-empty", "-m", "small")
	for start := time.Now(); ; {
		out, err := gitIn(work, env, "push", "-q", "origin", "HEAD:agent/small")
		if err == nil {
			break
		}
		if time.Since(start) > 5*time.Second || !strings.Contains(out, "too many pushes") {
			t.Fatalf("push after a client went away: %s", out)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if left, _ := os.ReadDir(filepath.Join(tmp2, "spool")); len(left) > 0 {
		t.Errorf("the small spool kept %d files", len(left))
	}
}

// syncBuffer is a bytes.Buffer the fake's goroutines can write while the
// test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.b.Bytes())
}
