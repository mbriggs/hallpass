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

// An allowed name that GitHub now serves under another name is refused
// before the gate reaches GitHub, so a rename can't carry the allowlist to
// a repo it doesn't cover.
func TestGateRefusesOldName(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sock := socketPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := &Server{
		Config:    &config.Config{SSH: &config.Key{}, Repos: []config.Repo{{Match: "acme/old"}, {Match: "acme/down"}}},
		Signer:    key,
		Log:       slog.New(slog.DiscardHandler),
		Permitted: func(peer.Peer) bool { return true },
		Addr:      "127.0.0.1:1", // never dialed: every case refuses first
		CurrentName: func(ctx context.Context, r github.Repo) (github.Repo, error) {
			// The real lookup is an HTTP request, which fails at once on a
			// context that's already done.
			if err := ctx.Err(); err != nil {
				return github.Repo{}, err
			}
			if r.Name == "down" {
				return github.Repo{}, errors.New("GitHub answered 502")
			}
			return github.Repo{Owner: "other", Name: "private"}, nil
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
	if got := ask("git-upload-pack", "acme/old"); !strings.Contains(got, "acme/old is now other/private") {
		t.Errorf("old name: %q", got)
	}
	if got := ask("git-upload-pack", "acme/down"); !strings.Contains(got, "couldn't check acme/down's current name") {
		t.Errorf("lookup failure: %q", got)
	}
	// Only fetch and push reach GitHub, even for a repo in the allowlist.
	if got := ask("git-upload-archive", "acme/old"); !strings.Contains(got, "only runs git fetch and push") {
		t.Errorf("other service: %q", got)
	}
}
