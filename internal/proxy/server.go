// Package proxy is where gh reaches GitHub. gh sends plain HTTP over the
// broker's Unix socket. The broker checks each request, builds a new one from
// what it parsed, adds the token, and sends that to GitHub over TLS. gh never
// holds the token, so a client that goes around the broker reaches GitHub
// with no credential.
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/peer"
)

// Server serves the gh socket.
type Server struct {
	Config *config.Config
	Token  string
	Log    *slog.Logger
	// Permitted decides which peers may use the broker.
	Permitted func(peer.Peer) bool
	// Upstream sends requests to GitHub. Nil uses a client that never
	// follows redirects, so the token never goes anywhere GitHub points.
	Upstream *http.Client

	mu            sync.Mutex
	names         map[string]cachedName
	rateRemaining int
	rateReset     time.Time
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

func (s *Server) httpServer(h http.Handler) *http.Server {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ctxKey{}, peer.Of(c))
		},
	}
	// HTTP/1.1 only: no h2c, no upgrades.
	var protos http.Protocols
	protos.SetHTTP1(true)
	srv.Protocols = &protos
	return srv
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

// flushCopy streams src to dst, flushing rw after each chunk, so gh sees
// long responses like run logs as GitHub sends them.
func flushCopy(dst io.Writer, rw http.ResponseWriter, src io.Reader) {
	rc := http.NewResponseController(rw)
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			return
		}
	}
}
