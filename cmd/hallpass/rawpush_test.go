package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/peer"
	"github.com/mbriggs/hallpass/internal/sshgate"
)

// rawRig is a gate in front of a fake GitHub, for pushes git itself
// wouldn't send: a hostile client writes the wrapper's protocol by hand.
type rawRig struct {
	t     *testing.T
	bare  string
	seed  string
	sock  string
	gate  *sshgate.Server
	log   *syncBuffer
	plain []string
}

const zeroOID = "0000000000000000000000000000000000000000"

var widgets = github.Repo{Owner: "acme", Name: "widgets"}

func newRawRig(t *testing.T) *rawRig {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	tmp, err := os.MkdirTemp("/tmp", "hpraw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	r := &rawRig{t: t, log: new(syncBuffer)}
	r.plain = []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x"}
	root := filepath.Join(tmp, "gh")
	r.bare = filepath.Join(root, "acme", "widgets.git")
	r.seed = filepath.Join(tmp, "seed")
	r.git(tmp, "init", "-q", "--bare", "-b", "main", r.bare)
	r.git(tmp, "init", "-q", "-b", "main", r.seed)
	r.git(r.seed, "commit", "-q", "--allow-empty", "-m", "seed")
	r.git(r.seed, "push", "-q", r.bare, "main", "main:colleague")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(&key.PublicKey)
	addr, hostKey := fakeGitHubSSH(t, root, pub, func(string, []string) io.Writer { return nil })
	r.sock = filepath.Join(tmp, "ssh.sock")
	ln, err := net.Listen("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	spool, err := sshgate.OpenSpool(filepath.Join(tmp, "spool"), sshgate.MaxSpool)
	if err != nil {
		t.Fatal(err)
	}
	r.gate = &sshgate.Server{
		Config: &config.Config{
			SSH:               &config.Key{},
			Repos:             []config.Repo{{Match: "acme/widgets"}},
			ProtectedBranches: []string{"main", "release/*"},
		},
		Signer:    key,
		Ledger:    sshgate.OpenLedger(""),
		Spool:     spool,
		Log:       slog.New(slog.NewTextHandler(r.log, nil)),
		Permitted: func(p peer.Peer) bool { return p.Known && p.UID == uint32(os.Getuid()) },
		Addrs:     []string{addr},
		HostKeys:  []string{hostKey},
	}
	go func() { _ = r.gate.Serve(ln) }()
	return r
}

func (r *rawRig) git(dir string, args ...string) string {
	r.t.Helper()
	out, err := r.gitTry(dir, args...)
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

func (r *rawRig) gitTry(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir, cmd.Env = dir, append(os.Environ(), r.plain...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// commit makes a commit in seed that GitHub doesn't have, and returns its
// ID and a pack that holds it.
func (r *rawRig) commit(msg string) (oid string, pack []byte) {
	r.t.Helper()
	r.git(r.seed, "commit", "-q", "--allow-empty", "-m", msg)
	oid = r.git(r.seed, "rev-parse", "HEAD")
	cmd := exec.Command("git", "pack-objects", "--stdout", "--revs", "-q")
	cmd.Dir, cmd.Env = r.seed, append(os.Environ(), r.plain...)
	cmd.Stdin = strings.NewReader(oid + "\n")
	pack, err := cmd.Output()
	if err != nil {
		r.t.Fatal(err)
	}
	return oid, pack
}

func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// push sends one receive-pack command and a pack, as a client that writes
// the protocol by hand would, and returns what the gate answered.
func (r *rawRig) push(command string, pack []byte) (stdout, stderr string) {
	r.t.Helper()
	c, err := net.Dial("unix", r.sock)
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	hdr, _ := json.Marshal(sshgate.Header{Service: "git-receive-pack", Repo: "acme/widgets"})
	if _, err := c.Write(append(hdr, '\n')); err != nil {
		r.t.Fatal(err)
	}
	var so, se bytes.Buffer
	read := func() bool {
		kind, data, err := sshgate.ReadFrame(c)
		if err != nil {
			return false
		}
		switch kind {
		case sshgate.FrameStdout:
			so.Write(data)
		case sshgate.FrameStderr:
			se.Write(data)
		case sshgate.FrameExit:
			return false
		}
		return true
	}
	// GitHub's ref list comes first, and ends in a flush packet.
	for !bytes.HasSuffix(so.Bytes(), []byte("0000")) {
		if !read() {
			r.t.Fatalf("no ref list: %s", se.String())
		}
	}
	so.Reset()
	body := append([]byte(pktLine(command+"\n")+"0000"), pack...)
	if _, err := c.Write(body); err != nil {
		r.t.Fatal(err)
	}
	_ = c.(*net.UnixConn).CloseWrite()
	for read() {
	}
	return so.String(), se.String()
}

// The ledger passes a delete whose old commit is the one agents last
// pushed. receive-pack doesn't compare a delete's old commit once the repo
// no longer has that commit, so the gate compares it with GitHub's ref
// list itself.
func TestDeleteMustStartFromGitHubsCommit(t *testing.T) {
	t.Parallel()
	r := newRawRig(t)
	oid, pack := r.commit("the agent's")
	if out, _ := r.push(zeroOID+" "+oid+" refs/heads/agent/b\x00report-status", pack); !strings.Contains(out, "ok refs/heads/agent/b") {
		t.Fatalf("setup push: %q", out)
	}
	if tip := r.gate.Ledger.Tip(widgets, "agent/b"); tip != oid {
		t.Fatalf("ledger has %q, want %s", tip, oid)
	}
	// The user takes the branch over with their own history, and the
	// agent's commit, now unreachable, is pruned.
	user := r.git(r.bare, "rev-parse", "refs/heads/colleague")
	r.git(r.bare, "update-ref", "refs/heads/agent/b", user)
	r.git(r.bare, "reflog", "expire", "--expire=now", "--all")
	r.git(r.bare, "gc", "-q", "--prune=now")
	if _, err := r.gitTry(r.bare, "cat-file", "-e", oid); err == nil {
		t.Fatal("setup: GitHub still has the agent's commit")
	}

	out, _ := r.push(oid+" "+zeroOID+" refs/heads/agent/b\x00report-status", nil)
	if want := "ng refs/heads/agent/b hallpass: this push starts from " + oid[:7] + ", and GitHub has the branch at " + user[:7]; !strings.Contains(out, want) {
		t.Errorf("answer %q, want %q", out, want)
	}
	if got := r.git(r.bare, "rev-parse", "refs/heads/agent/b"); got != user {
		t.Errorf("the user's branch is at %q, want %s", got, user)
	}

	// An update from the stale commit is refused the same way, and so is a
	// create over a branch GitHub has.
	next, pack := r.commit("the agent's next")
	if out, _ := r.push(oid+" "+next+" refs/heads/agent/b\x00report-status", pack); !strings.Contains(out, "ng refs/heads/agent/b hallpass: this push starts from") {
		t.Errorf("stale update: %q", out)
	}
	if out, _ := r.push(zeroOID+" "+next+" refs/heads/agent/b\x00report-status", pack); !strings.Contains(out, "ng refs/heads/agent/b hallpass: GitHub already has this branch") {
		t.Errorf("create over a branch: %q", out)
	}
	if got := r.git(r.bare, "rev-parse", "refs/heads/agent/b"); got != user {
		t.Errorf("the user's branch is at %q, want %s", got, user)
	}
}
