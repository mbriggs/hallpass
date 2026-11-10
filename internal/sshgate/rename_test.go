package sshgate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/peer"
)

// The gate follows a rename or transfer only when the allowlist covers
// both names, and applies the new name's rule, so a rename can't carry the
// allowlist to a repo it doesn't cover.
func TestGateChecksBothNames(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sock := socketPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	renamed := map[string]string{
		"acme/old":   "other/private",
		"acme/moved": "acme/new",
		"acme/rw":    "acme/ro",
	}
	s := &Server{
		Config: &config.Config{SSH: &config.Key{}, Repos: []config.Repo{
			{Match: "acme/old"}, {Match: "acme/down"},
			{Match: "acme/moved"}, {Match: "acme/new"},
			{Match: "acme/rw"}, {Match: "acme/ro", Access: "read"},
		}},
		Signer:    key,
		Log:       slog.New(slog.DiscardHandler),
		Permitted: func(peer.Peer) bool { return true },
		// Nothing listens here, so a request that passes every check
		// fails to reach GitHub.
		Addrs: []string{"127.0.0.1:1"},
		CurrentName: func(ctx context.Context, r github.Repo) (github.Repo, error) {
			// The real lookup is an HTTP request, which fails at once on a
			// context that's already done.
			if err := ctx.Err(); err != nil {
				return github.Repo{}, err
			}
			if r.Name == "down" {
				return github.Repo{}, errors.New("GitHub answered 502")
			}
			if to, ok := renamed[r.String()]; ok {
				return github.ParseRepo(to)
			}
			return r, nil
		},
	}
	go s.Serve(ln)

	ask := func(service, repo string) string {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		hdr, _ := json.Marshal(Header{Service: service, Repo: repo})
		c.Write(append(hdr, '\n'))
		return stderr(t, c)
	}
	for _, c := range []struct{ service, repo, want string }{
		{"git-upload-pack", "acme/old", "acme/old is now other/private on GitHub, and hallpass checks both names: other/private isn't in hallpass's allowlist"},
		{"git-upload-pack", "acme/down", "couldn't check acme/down's current name"},
		{"git-upload-pack", "acme/moved", "couldn't reach GitHub over SSH"},
		{"git-receive-pack", "acme/moved", "couldn't reach GitHub over SSH"},
		{"git-upload-pack", "acme/rw", "couldn't reach GitHub over SSH"},
		{"git-receive-pack", "acme/rw", "acme/rw is now acme/ro on GitHub, and hallpass checks both names: agents may only read acme/ro"},
		// Only fetch and push reach GitHub, even for a repo in the allowlist.
		{"git-upload-archive", "acme/old", "only runs git fetch and push"},
	} {
		if got := ask(c.service, c.repo); !strings.Contains(got, c.want) {
			t.Errorf("%s %s: got %q, want %q", c.service, c.repo, got, c.want)
		}
	}
}
