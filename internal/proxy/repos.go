package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mbriggs/hallpass/internal/github"
)

// currentNameTTL is how long CurrentName trusts an answer. A rename takes
// effect at most this long after it happens.
const currentNameTTL = 10 * time.Minute

type cachedName struct {
	repo github.Repo
	at   time.Time
}

// CurrentName asks GitHub what repo is called now. GitHub keeps an old name
// working after a rename or transfer, by redirecting the API and by serving
// git under it, so a name the allowlist covers can lead to a repo it
// doesn't. The SSH gate compares the answer with the name it was given.
func (s *Server) CurrentName(ctx context.Context, repo github.Repo) (github.Repo, error) {
	s.mu.Lock()
	c, ok := s.names[repo.Key()]
	s.mu.Unlock()
	if ok && time.Since(c.at) < currentNameTTL {
		return c.repo, nil
	}

	url := s.Config.API() + "/repos/" + repo.Owner + "/" + repo.Name
	resp, err := s.getRepo(ctx, url)
	if err != nil {
		return github.Repo{}, err
	}
	defer resp.Body.Close()
	// A renamed or transferred repo answers with a redirect to its ID. The
	// upstream client never follows redirects, so follow this one here, and
	// only to GitHub's own API, since the request carries the token.
	if resp.StatusCode/100 == 3 {
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, s.Config.API()+"/") {
			return github.Repo{}, fmt.Errorf("GitHub redirected %s somewhere hallpass doesn't follow", repo)
		}
		resp.Body.Close()
		if resp, err = s.getRepo(ctx, loc); err != nil {
			return github.Repo{}, err
		}
		defer resp.Body.Close()
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return github.Repo{}, fmt.Errorf("GitHub has no repo %s that hallpass's token can see", repo)
	case resp.StatusCode != http.StatusOK:
		return github.Repo{}, errors.New("GitHub answered " + resp.Status)
	}
	var r struct {
		FullName string `json:"full_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r); err != nil {
		return github.Repo{}, err
	}
	cur, err := github.ParseRepo(r.FullName)
	if err != nil {
		return github.Repo{}, fmt.Errorf("GitHub named %s as %q: %w", repo, r.FullName, err)
	}

	s.mu.Lock()
	if s.names == nil {
		s.names = map[string]cachedName{}
	}
	s.names[repo.Key()] = cachedName{cur, time.Now()}
	s.mu.Unlock()
	return cur, nil
}

func (s *Server) getRepo(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+s.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "hallpass")
	resp, err := s.upstream().Do(req)
	if err != nil {
		return nil, err
	}
	s.noteRate(resp)
	return resp, nil
}
