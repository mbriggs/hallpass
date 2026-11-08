package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
)

// CurrentName follows GitHub's redirect for a renamed repo to its new name,
// and only within GitHub's API.
func TestCurrentName(t *testing.T) {
	var renamed atomic.Bool
	var api string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/repos/acme/widgets":
			if renamed.Load() {
				w.Header().Set("Location", api+"/repositories/7")
				w.WriteHeader(http.StatusMovedPermanently)
				return
			}
			io.WriteString(w, `{"full_name":"acme/widgets"}`)
		case "/api/repos/acme/old":
			// What GitHub answers for a renamed or transferred repo.
			w.Header().Set("Location", api+"/repositories/7")
			w.WriteHeader(http.StatusMovedPermanently)
		case "/api/repositories/7":
			io.WriteString(w, `{"full_name":"other/private"}`)
		case "/api/repos/acme/elsewhere":
			w.Header().Set("Location", "https://evil.example/repositories/7")
			w.WriteHeader(http.StatusMovedPermanently)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer up.Close()
	api = up.URL + "/api"
	s := &Server{Config: &config.Config{APIURL: api}, Token: testToken, Log: slog.New(slog.DiscardHandler)}
	name := func(r string) (string, error) {
		repo, _ := github.ParseRepo(r)
		cur, err := s.CurrentName(context.Background(), repo)
		return cur.String(), err
	}

	if got, err := name("acme/widgets"); err != nil || got != "acme/widgets" {
		t.Errorf("unchanged repo: %q, %v", got, err)
	}
	if got, err := name("acme/old"); err != nil || got != "other/private" {
		t.Errorf("renamed repo: %q, %v", got, err)
	}
	if _, err := name("acme/gone"); err == nil || !strings.Contains(err.Error(), "no repo acme/gone") {
		t.Errorf("missing repo: %v", err)
	}
	if _, err := name("acme/elsewhere"); err == nil || !strings.Contains(err.Error(), "doesn't follow") {
		t.Errorf("redirect off GitHub's API: %v", err)
	}

	// A rename right after a lookup shows on the next one: nothing is
	// cached.
	renamed.Store(true)
	if got, err := name("acme/widgets"); err != nil || got != "other/private" {
		t.Errorf("repo renamed since the last lookup: %q, %v", got, err)
	}
}
