package sshgate

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/peer"
	"github.com/mbriggs/hallpass/internal/policy"
)

// GitHubHostKeys are the keys GitHub publishes at api.github.com/meta. The
// broker talks to nothing else.
var GitHubHostKeys = []string{
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
	"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
}

// Server serves the SSH socket.
type Server struct {
	Config    *config.Config
	Signer    crypto.Signer
	Ledger    *Ledger
	Log       *slog.Logger
	Permitted func(peer.Peer) bool
	// Addr and HostKeys default to github.com:22 and GitHubHostKeys. Tests
	// point them at a local server.
	Addr     string
	HostKeys []string
	// CurrentName asks GitHub what a repo is called now, so an old name
	// left by a rename or transfer can't reach a repo the allowlist
	// doesn't cover. Nil, as on a machine with no token, skips the check.
	CurrentName func(context.Context, github.Repo) (github.Repo, error)

	limits limits
}

// limits bounds the gate's connections: how many it serves at once, how
// long a client has to send its header, and how long a connection may go
// with nothing moving in either direction. Zero fields take the defaults;
// tests set tighter ones.
type limits struct {
	conns      int
	headerWait time.Duration
	idle       time.Duration
}

func (l limits) withDefaults() limits {
	if l.conns == 0 {
		l.conns = 64
	}
	if l.headerWait == 0 {
		l.headerWait = 10 * time.Second
	}
	if l.idle == 0 {
		l.idle = 10 * time.Minute
	}
	return l
}

func (s *Server) Serve(ln net.Listener) error {
	lim := s.limits.withDefaults()
	slots := make(chan struct{}, lim.conns)
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				s.handle(c, lim)
			}()
		default:
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				s.Log.Warn("refused", "via", "ssh", "reason", "too many git connections")
				_ = WriteFrame(c, FrameStderr, []byte("hallpass: the broker is handling too many git connections; try again\n"))
				_ = WriteFrame(c, FrameExit, []byte{1})
			}()
		}
	}
}

// idleConn pushes its deadline forward by timeout on every read and write,
// so a long clone keeps going while a connection where nothing moves is
// cut. SetDeadline moves the deadline of a read or write already waiting,
// so traffic either way keeps both alive.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(p)
}

// out serializes frames from the goroutines relaying stdout and stderr.
type out struct {
	mu sync.Mutex
	w  io.Writer
}

func (o *out) frame(kind byte, data []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return WriteFrame(o.w, kind, data)
}

func (o *out) writer(kind byte) io.Writer {
	return frameFunc(func(p []byte) error { return o.frame(kind, p) })
}

type frameFunc func([]byte) error

func (f frameFunc) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		c := min(len(p), 64<<10)
		if err := f(p[:c]); err != nil {
			return 0, err
		}
		p = p[c:]
	}
	return n, nil
}

func (s *Server) handle(conn net.Conn, lim limits) {
	defer conn.Close()
	// peer.Of needs the Unix socket itself, so wrap only after it.
	p := peer.Of(conn)
	// The header comes first and is small, so it gets headerWait; the
	// transfer after it gets idle.
	ic := &idleConn{Conn: conn, timeout: lim.headerWait}
	conn = ic
	log := s.Log.With("via", "ssh", "uid", p.UID, "pid", p.PID, "procs", p.Procs)
	o := &out{w: conn}
	fail := func(msg string, attrs ...any) {
		log.Warn("refused", append([]any{"reason", msg}, attrs...)...)
		_ = o.frame(FrameStderr, []byte("hallpass: "+msg+"\n"))
		_ = o.frame(FrameExit, []byte{1})
	}
	if !s.Permitted(p) {
		fail("this uid may not use hallpass")
		return
	}
	in := bufio.NewReader(conn)
	line, err := in.ReadSlice('\n')
	ic.timeout = lim.idle
	if err != nil {
		fail("malformed request")
		return
	}
	var h Header
	if err := json.Unmarshal(line, &h); err != nil {
		fail("malformed request")
		return
	}
	repo, err := github.ParseRepo(h.Repo)
	if err != nil || (h.Service != "git-upload-pack" && h.Service != "git-receive-pack") {
		fail("hallpass only runs git fetch and push over SSH")
		return
	}
	log = log.With("repo", repo.String(), "op", strings.TrimPrefix(h.Service, "git-"))
	write := h.Service == "git-receive-pack"
	rule, ok := s.Config.Allowed(repo)
	switch {
	case !ok:
		fail(repo.String() + " isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow " + repo.String())
		return
	case write && !rule.Write:
		fail("agents may only read " + repo.String())
		return
	case s.Signer == nil:
		fail("this machine has no SSH key. Create one: sudo /opt/hallpass/bin/hallpass ssh-key create")
		return
	}
	if s.CurrentName != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cur, err := s.CurrentName(ctx, repo)
		cancel()
		if err != nil {
			fail("couldn't check " + repo.String() + "'s current name with GitHub: " + err.Error())
			return
		}
		if !strings.EqualFold(cur.String(), repo.String()) {
			fail(repo.String() + " is now " + cur.String() + " on GitHub. Use the new name, which hallpass checks against its allowlist")
			return
		}
	}

	client, err := s.dial()
	if err != nil {
		fail("couldn't reach GitHub over SSH: "+err.Error(), "err", err)
		return
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		fail("couldn't open an SSH session: " + err.Error())
		return
	}
	defer sess.Close()
	if h.GitProtocol == "version=2" {
		_ = sess.Setenv("GIT_PROTOCOL", "version=2")
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	sess.Stderr = o.writer(FrameStderr)
	if err := sess.Start(fmt.Sprintf("%s '%s/%s.git'", h.Service, repo.Owner, repo.Name)); err != nil {
		fail("GitHub refused the command: " + err.Error())
		return
	}

	if write {
		if !s.relayPush(client, repo, rule.Ops, in, stdin, stdout, o, log, p.Procs) {
			_ = o.frame(FrameExit, []byte{0})
			return
		}
	} else {
		go func() {
			_, _ = io.Copy(stdin, in)
			stdin.Close()
		}()
		_, _ = io.Copy(o.writer(FrameStdout), stdout)
	}
	code := byte(0)
	if err := sess.Wait(); err != nil {
		if ee, ok := errors.AsType[*ssh.ExitError](err); ok {
			code = byte(ee.ExitStatus()) //nolint:gosec // ssh exit statuses are 0-255
		} else {
			code = 1
		}
	}
	_ = o.frame(FrameExit, []byte{code})
	log.Info("allowed", "exit", code)
}

// relayPush runs a receive-pack exchange, checking the push before any of it
// reaches GitHub. It returns false when it refused the push and answered git
// itself.
func (s *Server) relayPush(client *ssh.Client, repo github.Repo, ops op.Set, in *bufio.Reader, stdin io.WriteCloser, stdout io.Reader, o *out, log *slog.Logger, procs string) bool {
	up := bufio.NewReader(stdout)
	adv, err := readAdvertisement(up)
	if err != nil {
		_ = o.frame(FrameStderr, []byte("hallpass: couldn't read GitHub's ref list: "+err.Error()+"\n"))
		return false
	}
	_ = o.frame(FrameStdout, noThin(adv))

	// Ask for the default branch while git sends its commands, so the round
	// trip to GitHub overlaps with git's.
	type branch struct {
		name string
		err  error
	}
	defCh := make(chan branch, 1)
	go func() {
		name, err := s.defaultBranch(client, repo)
		defCh <- branch{name, err}
	}()

	push, err := policy.ReadPush(in)
	if err != nil {
		log.Warn("refused", "reason", err.Error())
		_ = o.frame(FrameStderr, []byte("hallpass: "+err.Error()+"\n"))
		return false
	}
	if push.Probe || len(push.Updates) == 0 {
		_, _ = stdin.Write([]byte("0000"))
		stdin.Close()
		_, _ = io.Copy(o.writer(FrameStdout), up)
		return true
	}
	def := <-defCh
	if def.err != nil {
		_ = o.frame(FrameStderr, []byte("hallpass: couldn't check the default branch: "+def.err.Error()+"\n"))
		return false
	}
	check := func(def string) map[string]string {
		return policy.CheckPush(push, policy.Branches{
			Default:   def,
			Ops:       ops,
			Protected: s.Config.ProtectedBranches,
			Tip:       func(b string) string { return s.Ledger.Tip(repo, b) },
			Repo:      repo,
		})
	}
	refused := check(def.name)
	refuse := func(refused map[string]string) bool {
		log.Warn("refused", "reason", "push", "refs", refused)
		// git reads the answer after it sends the pack, so take the pack
		// first. Nothing of it goes to GitHub. A push of only deletes has
		// no pack, and git waits for the answer with stdin still open.
		if push.HasPack() {
			_, _ = io.Copy(io.Discard, io.LimitReader(in, 1<<30))
		}
		_ = o.frame(FrameStdout, policy.RefusePush(push, refused))
		return false
	}
	if len(refused) > 0 {
		return refuse(refused)
	}

	// GitHub doesn't stop SSH pushes that change workflows, so the broker
	// reads the pack and checks before sending any of it.
	var pack bytes.Buffer
	if push.HasPack() {
		p, err := policy.ReadPack(io.TeeReader(io.LimitReader(in, maxPack), &pack))
		if err != nil {
			return refuse(all(push, err.Error()))
		}
		head := refOID(adv, "refs/heads/"+def.name)
		refused, err := policy.WorkflowChanges(p, push.Updates, head, func(commits []string) (map[string]policy.Object, error) {
			return fetchTrees(client, repo, commits)
		})
		if err != nil {
			return refuse(all(push, "hallpass couldn't check this push for workflow changes: "+err.Error()))
		}
		if len(refused) > 0 {
			return refuse(refused)
		}
		// The client decides how long its pack takes, and the default
		// branch can change meanwhile, say to a branch this push updates.
		// So ask again, and check against the default as it is now.
		name, err := s.defaultBranch(client, repo)
		if err != nil {
			return refuse(all(push, "hallpass couldn't check the default branch: "+err.Error()))
		}
		if name != def.name {
			def.name = name
			if refused := check(name); len(refused) > 0 {
				return refuse(refused)
			}
		}
	}

	_, _ = stdin.Write(push.Raw)
	_, _ = stdin.Write(pack.Bytes())
	go func() {
		_, _ = io.Copy(stdin, in)
		stdin.Close()
	}()
	var report bytes.Buffer
	_, _ = io.Copy(io.MultiWriter(o.writer(FrameStdout), &capped{&report, 1 << 20}), up)
	accepted := policy.ReportStatus(report.Bytes(), push.SideBand())
	// Record where each accepted branch now points, so agents can go on
	// from there and from nowhere else. The default branch stays out:
	// push.default governs it, not the ledger.
	for _, ref := range accepted {
		for _, u := range push.Updates {
			if u.Ref != ref || u.Branch() == "" || strings.EqualFold(u.Branch(), def.name) {
				continue
			}
			tip := u.New
			if u.Delete() {
				tip = ""
			}
			if err := s.Ledger.Record(repo, u.Branch(), tip, procs); err != nil {
				log.Error("ledger write failed; after a restart agents can't update this branch", "branch", u.Branch(), "err", err)
			}
		}
	}
	log.Info("pushed", "refs", accepted)
	return true
}

// maxPack bounds the pack the broker holds while it checks a push.
const maxPack = 512 << 20

func all(p policy.Push, reason string) map[string]string {
	m := map[string]string{}
	for _, u := range p.Updates {
		m[u.Ref] = reason
	}
	return m
}

// refOID finds ref's commit in a ref list, or "" when the list doesn't have
// it, as for an empty repo.
func refOID(adv []byte, ref string) string {
	r := bufio.NewReader(bytes.NewReader(adv))
	for {
		line, kind, err := pkt(r)
		if err != nil || kind == flush {
			return ""
		}
		line, _, _ = bytes.Cut(bytes.TrimSuffix(line, []byte("\n")), []byte{0})
		oid, name, ok := bytes.Cut(line, []byte(" "))
		if ok && string(name) == ref && len(oid) == 40 {
			return string(oid)
		}
	}
}

// readAdvertisement reads receive-pack's ref list, up to its flush packet.
func readAdvertisement(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		buf.Write(hdr[:])
		var n int
		if _, err := fmt.Sscanf(string(hdr[:]), "%04x", &n); err != nil {
			return nil, errors.New("malformed pkt-line")
		}
		if n == 0 {
			return buf.Bytes(), nil
		}
		if n < 4 || n > 65520 {
			return nil, errors.New("malformed pkt-line")
		}
		if _, err := io.CopyN(&buf, r, int64(n-4)); err != nil {
			return nil, err
		}
	}
}

// defaultBranch reads HEAD's target from upload-pack's ref list, on a second
// session over the same connection. It's "" only for an empty repo.
func (s *Server) defaultBranch(client *ssh.Client, repo github.Repo) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.Start(fmt.Sprintf("git-upload-pack '%s/%s.git'", repo.Owner, repo.Name)); err != nil {
		return "", err
	}
	adv, err := readAdvertisement(bufio.NewReader(stdout))
	_, _ = stdin.Write([]byte("0000"))
	stdin.Close()
	if err != nil {
		return "", err
	}
	return headBranch(adv)
}

// headBranch reads the default branch from an upload-pack ref list. A list
// with no HEAD is an empty repo only when it lists no refs either. Anything
// else, like a dangling HEAD, is an error, because "" lets the first push
// through as the new default.
func headBranch(adv []byte) (string, error) {
	_, after, ok := bytes.Cut(adv, []byte("symref=HEAD:refs/heads/"))
	if ok {
		end := bytes.IndexAny(after, " \n\x00")
		if end < 0 {
			end = len(after)
		}
		if end == 0 {
			return "", errors.New("GitHub's ref list names an empty default branch")
		}
		return string(after[:end]), nil
	}
	if bytes.Contains(adv, []byte(" refs/")) {
		return "", errors.New("GitHub's ref list has branches but no default branch")
	}
	return "", nil
}

// Check confirms GitHub accepts the key. GitHub answers a session with no
// command by greeting the account the key belongs to, and then closing it.
func (s *Server) Check() (string, error) {
	client, err := s.dial()
	if err != nil {
		return "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	// Read the channel's streams directly. They work whether or not GitHub
	// answers the shell request before closing, and each has one reader.
	// Sharing one buffer between the session's stdout and stderr copiers
	// raced, and lost the greeting about half the time.
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return "", err
	}
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
	_ = sess.Shell()
	// "Hi mbriggs! You've successfully authenticated, but GitHub does not
	// provide shell access."
	b, err := io.ReadAll(io.LimitReader(stderr, 4096))
	if err != nil {
		return "", err
	}
	msg := string(b)
	if login, _, ok := strings.Cut(strings.TrimPrefix(msg, "Hi "), "!"); ok && strings.HasPrefix(msg, "Hi ") {
		return login, nil
	}
	return "", fmt.Errorf("GitHub didn't recognize the key: %s", strings.TrimSpace(msg))
}

func (s *Server) dial() (*ssh.Client, error) {
	signer, err := ssh.NewSignerFromSigner(s.Signer)
	if err != nil {
		return nil, err
	}
	keys := s.HostKeys
	if keys == nil {
		keys = GitHubHostKeys
	}
	var pinned []ssh.PublicKey
	var algs []string
	for _, k := range keys {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			return nil, err
		}
		pinned = append(pinned, pk)
		algs = append(algs, pk.Type())
	}
	addr := s.Addr
	if addr == "" {
		addr = "github.com:22"
	}
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:              "git",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyAlgorithms: algs,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			for _, pk := range pinned {
				if bytes.Equal(pk.Marshal(), key.Marshal()) {
					return nil
				}
			}
			return errors.New("GitHub's host key doesn't match the keys GitHub publishes")
		},
		Timeout: 20 * time.Second,
	})
}

type capped struct {
	buf *bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
