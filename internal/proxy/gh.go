package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/policy"
)

// rateReserve is how many API requests an hour hallpass leaves for the user's
// own use of the token's account.
const rateReserve = 1000

// ServeGH serves gh's plain HTTP on ln.
func (s *Server) ServeGH(ln net.Listener) error {
	err := s.httpServer(http.HandlerFunc(s.serveGH)).Serve(ln)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) serveGH(w http.ResponseWriter, r *http.Request) {
	p := peerFrom(r.Context())
	log := s.Log.With("via", "gh", "uid", p.UID, "pid", p.PID, "procs", p.Procs)
	graphql := r.Method == "POST" && r.RequestURI == "/graphql"
	refuse := func(status int, msg string, attrs ...any) {
		log.Warn("refused", append([]any{"reason", msg}, attrs...)...)
		w.Header().Set("Content-Type", "application/json")
		if graphql {
			// gh prints GraphQL errors as "GraphQL: <message>".
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"type": "FORBIDDEN", "message": "hallpass: " + msg}}})
			return
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"message": "hallpass: " + msg})
	}

	switch {
	case !s.Permitted(p):
		refuse(http.StatusForbidden, "this uid may not use hallpass")
		return
	case r.Host != "api.github.com":
		refuse(http.StatusMisdirectedRequest, "hallpass only forwards requests to api.github.com")
		return
	case s.Token == "":
		refuse(http.StatusServiceUnavailable, "this machine has no GitHub token. Get one: sudo /opt/hallpass/bin/hallpass login")
		return
	case s.rateLow():
		refuse(http.StatusTooManyRequests, "the token's account is close to GitHub's hourly rate limit, so hallpass is holding the rest for you")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
	if err != nil || len(body) > 4<<20 {
		refuse(http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}

	var path string
	var upBody []byte
	var follow bool
	var strip []string
	if graphql {
		g, err := policy.ClassifyGraphQL(body, s.Config.Grants())
		if err != nil {
			refuse(http.StatusForbidden, err.Error())
			return
		}
		log = log.With("graphql", strings.Join(g.Fields, ","))
		if msg := s.checkGraphQL(r.Context(), g); msg != "" {
			refuse(http.StatusForbidden, msg)
			return
		}
		path, upBody = "/graphql", g.Body
	} else {
		rest, err := policy.ClassifyREST(r.Method, r.RequestURI, body, s.Config.Grants())
		if err != nil {
			refuse(http.StatusForbidden, err.Error())
			return
		}
		log = log.With("route", rest.Route)
		if rest.Repo != nil {
			log = log.With("repo", rest.Repo.String())
			rule, ok := s.Config.Allowed(*rest.Repo)
			switch {
			case !ok:
				refuse(http.StatusForbidden, rest.Repo.String()+" isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow "+rest.Repo.String())
				return
			case rest.Write && !rule.Write:
				refuse(http.StatusForbidden, "agents may only read "+rest.Repo.String())
				return
			}
			if err := policy.CheckOps(rest.Ops, rule.Ops, *rest.Repo); err != nil {
				refuse(http.StatusForbidden, err.Error())
				return
			}
		}
		if rest.Authored != "" {
			if ok, err := s.authored(r.Context(), rest.Authored); err != nil {
				refuse(http.StatusBadGateway, "couldn't check who wrote it: "+err.Error())
				return
			} else if !ok {
				refuse(http.StatusForbidden, "agents may only change PRs, issues, and comments you wrote")
				return
			}
		}
		path, upBody, follow, strip = rest.Path, rest.Body, rest.Follow, rest.Strip
	}

	var rd io.Reader = http.NoBody
	if upBody != nil {
		rd = bytes.NewReader(upBody)
	}
	up, err := http.NewRequestWithContext(r.Context(), r.Method, s.Config.API()+path, rd)
	if err != nil {
		refuse(http.StatusInternalServerError, err.Error())
		return
	}
	copyHeaders(up.Header, r.Header, "Accept", "User-Agent", "X-GitHub-Api-Version", "If-None-Match", "GraphQL-Features", "Time-Zone")
	if upBody != nil {
		up.Header.Set("Content-Type", "application/json")
	}
	up.Header.Set("Authorization", "token "+s.Token)
	resp, err := s.upstream().Do(up)
	if err != nil {
		refuse(http.StatusBadGateway, "couldn't reach GitHub: "+err.Error())
		return
	}
	defer resp.Body.Close()
	s.noteRate(resp)
	if msg := upstreamProblem(resp); msg != "" {
		refuse(http.StatusForbidden, msg)
		return
	}
	if follow && resp.StatusCode/100 == 3 {
		resp.Body.Close()
		if resp, err = s.followStorage(r.Context(), resp.Header.Get("Location")); err != nil {
			refuse(http.StatusBadGateway, err.Error())
			return
		}
		defer resp.Body.Close()
	}
	copyHeaders(w.Header(), resp.Header, "Content-Type", "Content-Encoding", "ETag", "Last-Modified", "Link",
		"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Used", "X-RateLimit-Resource",
		"X-GitHub-Request-Id", "Location", "Retry-After")
	if len(strip) > 0 && resp.StatusCode == http.StatusOK {
		var obj map[string]json.RawMessage
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&obj); err != nil {
			refuse(http.StatusBadGateway, "GitHub's answer wasn't JSON")
			return
		}
		for _, k := range strip {
			delete(obj, k)
		}
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(obj)
		log.Info("allowed", "status", resp.StatusCode)
		return
	}
	w.WriteHeader(resp.StatusCode)
	flushCopy(w, w, resp.Body)
	log.Info("allowed", "status", resp.StatusCode)
}

// checkGraphQL checks the repos and node IDs a GraphQL request names. It
// returns a refusal message, or "".
func (s *Server) checkGraphQL(ctx context.Context, g *policy.GraphQL) string {
	allowed := func(repo github.Repo) (bool, op.Set, bool) {
		rule, ok := s.Config.Allowed(repo)
		return rule.Write, rule.Ops, ok
	}
	for _, u := range g.Repos {
		write, _, ok := allowed(u.Repo)
		switch {
		case !ok:
			return u.Repo.String() + " isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow " + u.Repo.String()
		case u.Write && !write:
			return "agents may only read " + u.Repo.String()
		}
	}
	if len(g.Nodes) == 0 {
		if g.Mutation {
			return "mutation names nothing to check"
		}
		return ""
	}
	ids := make([]string, len(g.Nodes))
	for i, n := range g.Nodes {
		ids[i] = n.ID
	}
	nodes, err := s.resolve(ctx, ids)
	if err != nil {
		return "couldn't check which repo an ID belongs to: " + err.Error()
	}
	for _, use := range g.Nodes {
		n, ok := nodes[use.ID]
		if !ok {
			return "couldn't find " + use.Where + " on GitHub"
		}
		if err := policy.CheckNode(use, n, allowed); err != nil {
			return err.Error()
		}
	}
	return ""
}

// resolveQuery asks for what checking a node ID needs.
const resolveQuery = `query($ids:[ID!]!){nodes(ids:$ids){__typename
... on Repository{nameWithOwner}
... on PullRequest{repository{nameWithOwner} viewerDidAuthor}
... on Issue{repository{nameWithOwner} viewerDidAuthor}
... on IssueComment{repository{nameWithOwner} viewerDidAuthor}
... on PullRequestReview{repository{nameWithOwner} viewerDidAuthor}
... on PullRequestReviewComment{repository{nameWithOwner} viewerDidAuthor}
... on PullRequestReviewThread{repository{nameWithOwner}}}}`

// resolve asks GitHub which repo each node ID belongs to, its type, and
// whether the token's user wrote it. Results are cached, since an object's
// repo changes only when someone transfers it.
func (s *Server) resolve(ctx context.Context, ids []string) (map[string]policy.Node, error) {
	out := map[string]policy.Node{}
	var missing []string
	s.mu.Lock()
	for _, id := range ids {
		if n, ok := s.nodes[id]; ok && time.Since(n.at) < time.Hour {
			out[id] = n.Node
		} else {
			missing = append(missing, id)
		}
	}
	s.mu.Unlock()
	if len(missing) == 0 {
		return out, nil
	}
	b, _ := json.Marshal(map[string]any{"query": resolveQuery, "variables": map[string]any{"ids": missing}})
	req, err := http.NewRequestWithContext(ctx, "POST", s.Config.API()+"/graphql", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hallpass")
	resp, err := s.upstream().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	s.noteRate(resp)
	var r struct {
		Data struct {
			Nodes []*struct {
				Typename      string `json:"__typename"`
				NameWithOwner string `json:"nameWithOwner"`
				Repository    *struct {
					NameWithOwner string `json:"nameWithOwner"`
				} `json:"repository"`
				ViewerDidAuthor bool `json:"viewerDidAuthor"`
			} `json:"nodes"`
		} `json:"data"`
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("GitHub answered " + resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return nil, err
	}
	if len(r.Data.Nodes) != len(missing) {
		return nil, errors.New("GitHub returned the wrong number of nodes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodes == nil {
		s.nodes = map[string]cachedNode{}
	}
	for i, n := range r.Data.Nodes {
		if n == nil {
			continue
		}
		owner := n.NameWithOwner
		if n.Repository != nil {
			owner = n.Repository.NameWithOwner
		}
		repo, err := github.ParseRepo(owner)
		if err != nil {
			continue
		}
		node := policy.Node{Type: n.Typename, Repo: repo, Authored: n.ViewerDidAuthor}
		out[missing[i]] = node
		s.nodes[missing[i]] = cachedNode{node, time.Now()}
	}
	return out, nil
}

// authored reports whether the token's user wrote the object at path.
func (s *Server) authored(ctx context.Context, path string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.Config.API()+path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "token "+s.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "hallpass")
	resp, err := s.upstream().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("GitHub answered " + resp.Status)
	}
	var obj struct {
		User struct{ Login string } `json:"user"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&obj); err != nil {
		return false, err
	}
	login := ""
	if s.Config.Token != nil {
		login = s.Config.Token.Login
	}
	return login != "" && strings.EqualFold(obj.User.Login, login), nil
}

// storageHosts are where GitHub redirects downloads of run logs and
// artifacts. The URLs are signed, so they need no token.
var storageHosts = []string{".actions.githubusercontent.com", ".blob.core.windows.net", "objects.githubusercontent.com"}

func (s *Server) followStorage(ctx context.Context, loc string) (*http.Response, error) {
	u, err := url.Parse(loc)
	if err != nil || u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return nil, errors.New("GitHub redirected somewhere hallpass doesn't follow")
	}
	ok := false
	for _, h := range storageHosts {
		ok = ok || strings.HasSuffix(u.Hostname(), h) || u.Hostname() == strings.TrimPrefix(h, ".")
	}
	if !ok && !strings.HasPrefix(loc, s.Config.API()) {
		return nil, errors.New("GitHub redirected to " + u.Hostname() + ", which hallpass doesn't follow")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", loc, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hallpass")
	// A separate client, so the token can't follow.
	return (&http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
}

func (s *Server) noteRate(resp *http.Response) {
	rem, err := strconv.Atoi(resp.Header.Get("X-RateLimit-Remaining"))
	if err != nil || resp.Header.Get("X-RateLimit-Resource") == "search" {
		return
	}
	reset, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
	s.mu.Lock()
	s.rateRemaining, s.rateReset = rem, time.Unix(reset, 0)
	s.mu.Unlock()
}

func (s *Server) rateLow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.rateReset.IsZero() && time.Now().Before(s.rateReset) && s.rateRemaining < rateReserve
}
