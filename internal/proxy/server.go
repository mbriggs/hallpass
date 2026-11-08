// Package proxy is where git over HTTPS and gh reach GitHub. Clients send
// plain HTTP over the broker's Unix sockets: git through a SOCKS5 tunnel, gh
// directly. The broker checks each request, builds a new one from what it
// parsed, adds the token, and sends that to GitHub over TLS. Clients never
// hold the token, so a client that goes around the broker reaches GitHub
// with no credential.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/peer"
	"github.com/mbriggs/hallpass/internal/policy"
)

// Server serves the git and gh sockets.
type Server struct {
	Config *config.Config
	Token  string
	Ledger *Ledger
	Log    *slog.Logger
	// Permitted decides which peers may use the broker.
	Permitted func(peer.Peer) bool
	// Upstream sends requests to GitHub. Nil uses a client that never
	// follows redirects, so the token never goes anywhere GitHub points.
	Upstream *http.Client

	mu            sync.Mutex
	defaults      map[string]cachedBranch
	nodes         map[string]cachedNode
	rateRemaining int
	rateReset     time.Time
}

type cachedNode struct {
	policy.Node
	at time.Time
}

type cachedBranch struct {
	name    string
	fetched time.Time
}

type ctxKey struct{}

func peerFrom(ctx context.Context) peer.Peer {
	p, _ := ctx.Value(ctxKey{}).(peer.Peer)
	return p
}

func (s *Server) upstream() *http.Client {
	if s.Upstream != nil {
		return s.Upstream
	}
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ServeGit serves git's SOCKS5-then-HTTP connections on ln.
func (s *Server) ServeGit(ln net.Listener) error {
	conns := make(chan net.Conn)
	cl := &chanListener{addr: ln.Addr(), conns: conns, done: make(chan struct{})}
	go func() {
		defer cl.Close()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				p := peer.Of(c)
				if !s.Permitted(p) {
					s.Log.Warn("refused", "via", "git", "uid", p.UID, "procs", p.Procs, "reason", "uid not permitted")
					c.Close()
					return
				}
				if err := socksAccept(c); err != nil {
					s.Log.Warn("refused", "via", "git", "uid", p.UID, "procs", p.Procs, "reason", err.Error())
					c.Close()
					return
				}
				select {
				case conns <- &peerConn{Conn: c, peer: p}:
				case <-cl.done:
					c.Close()
				}
			}()
		}
	}()
	srv := s.httpServer(http.HandlerFunc(s.serveGit))
	err := srv.Serve(cl)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) httpServer(h http.Handler) *http.Server {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if pc, ok := c.(*peerConn); ok {
				return context.WithValue(ctx, ctxKey{}, pc.peer)
			}
			return context.WithValue(ctx, ctxKey{}, peer.Of(c))
		},
	}
	// HTTP/1.1 only: no h2c, no upgrades.
	var protos http.Protocols
	protos.SetHTTP1(true)
	srv.Protocols = &protos
	return srv
}

// defaultBranch asks GitHub for repo's default branch, cached for ten
// minutes. Pushes are refused when this fails, rather than guessed.
func (s *Server) defaultBranch(ctx context.Context, repo github.Repo) (string, error) {
	s.mu.Lock()
	c, ok := s.defaults[repo.Key()]
	s.mu.Unlock()
	if ok && time.Since(c.fetched) < 10*time.Minute {
		return c.name, nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", s.Config.API()+"/repos/"+repo.Owner+"/"+repo.Name, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+s.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "hallpass")
	resp, err := s.upstream().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub answered %d for %s", resp.StatusCode, repo)
	}
	var r struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || r.DefaultBranch == "" {
		return "", fmt.Errorf("GitHub didn't say what %s's default branch is", repo)
	}
	s.mu.Lock()
	if s.defaults == nil {
		s.defaults = map[string]cachedBranch{}
	}
	s.defaults[repo.Key()] = cachedBranch{r.DefaultBranch, time.Now()}
	s.mu.Unlock()
	return r.DefaultBranch, nil
}

// copyHeaders copies only the named headers.
func copyHeaders(dst, src http.Header, names ...string) {
	for _, n := range names {
		for _, v := range src.Values(n) {
			dst.Add(n, v)
		}
	}
}

// upstreamProblem turns GitHub's credential failures into messages that say
// what to do. It returns "" for anything else.
func upstreamProblem(resp *http.Response) string {
	if sso := resp.Header.Get("X-GitHub-SSO"); strings.HasPrefix(sso, "required") {
		_, u, _ := strings.Cut(sso, "url=")
		return "this org requires SAML SSO authorization for hallpass's token. Open " + u + " as yourself (the link works for an hour)"
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return "GitHub rejected hallpass's token. It expired or was revoked. Run sudo /opt/hallpass/bin/hallpass login, or install-pat"
	}
	return ""
}

type peerConn struct {
	net.Conn
	peer peer.Peer
}

// chanListener hands the HTTP server connections that already passed the
// uid check and the SOCKS handshake.
type chanListener struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }
