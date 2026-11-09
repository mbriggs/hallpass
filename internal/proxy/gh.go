package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
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
	graphql := r.Method == http.MethodPost && r.RequestURI == "/graphql"
	refuse := func(status int, msg string) {
		log.Warn("refused", "reason", msg)
		w.Header().Set("Content-Type", "application/json")
		if graphql {
			// gh prints GraphQL errors as "GraphQL: <message>".
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"type": "FORBIDDEN", "message": "hallpass: " + msg}}})
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "hallpass: " + msg})
	}

	switch {
	case !s.Permitted(p):
		// Close the connection, so another user on the machine can't
		// keep connections open on the broker.
		w.Header().Set("Connection", "close")
		refuse(http.StatusForbidden, "this uid may not use hallpass")
		return
	case r.Host != "api.github.com":
		refuse(http.StatusMisdirectedRequest, "hallpass only forwards requests to api.github.com")
		return
	}
	// tokenReady refuses when the token can't serve a request. Anonymous
	// reads don't need it.
	tokenReady := func() bool {
		switch {
		case s.Token == "":
			refuse(http.StatusServiceUnavailable, "this machine has no GitHub token. Get one: sudo /opt/hallpass/bin/hallpass login")
			return false
		case s.rateLow():
			refuse(http.StatusTooManyRequests, "the token's account is close to GitHub's hourly rate limit, so hallpass is holding the rest for you")
			return false
		}
		return true
	}
	// Only the body read gets a deadline. A server-wide ReadTimeout would
	// also cancel long log and artifact downloads.
	wait := s.bodyWait
	if wait == 0 {
		wait = 30 * time.Second
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(wait))
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// Close, rather than wait for the rest of a body that isn't coming.
		w.Header().Set("Connection", "close")
		refuse(http.StatusRequestTimeout, "the request body didn't arrive in time")
		return
	}
	_ = rc.SetReadDeadline(time.Time{})
	if err != nil || len(body) > 4<<20 {
		refuse(http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}

	var path string
	var upBody []byte
	var follow bool
	var strip []string
	if graphql {
		if !tokenReady() {
			return
		}
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
		var rule config.Rule
		listed := false
		if rest.Repo != nil {
			log = log.With("repo", rest.Repo.String())
			rule, listed = s.Config.Allowed(*rest.Repo)
		}
		if rest.Repo != nil && !listed {
			why := rest.Repo.String() + " isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow " + rest.Repo.String()
			if rest.Write {
				refuse(http.StatusForbidden, why)
				return
			}
			if !rest.Anonymous {
				rest.Route = "GET " + rest.Path + " (anonymous)"
			}
			rest.Anonymous, rest.Why = true, why
		}
		log = log.With("route", rest.Route)
		if rest.Anonymous {
			s.serveAnonymous(w, r, rest, log, refuse)
			return
		}
		if !tokenReady() {
			return
		}
		if rest.Repo != nil {
			if rest.Write && !rule.Write {
				refuse(http.StatusForbidden, "agents may only read "+rest.Repo.String())
				return
			}
			if rest.Authored != "" {
				ok, isPR, err := s.authored(r.Context(), rest.Authored)
				switch {
				case err != nil:
					refuse(http.StatusBadGateway, "couldn't check who wrote it: "+err.Error())
					return
				case !ok:
					refuse(http.StatusForbidden, "agents may only change PRs, issues, and comments you wrote")
					return
				case isPR:
					// GitHub serves PRs on the issues routes too, and editing
					// one there is pr.edit.
					for i, o := range rest.Ops {
						if o == op.IssueEdit {
							rest.Ops[i] = op.PREdit
						}
					}
				}
			}
			if err := policy.CheckOps(rest.Ops, rule.Ops, *rest.Repo); err != nil {
				refuse(http.StatusForbidden, err.Error())
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
	if len(strip) > 0 && resp.StatusCode/100 == 2 && strings.Contains(resp.Header.Get("Content-Type"), "json") {
		dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<20))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); errors.Is(err, io.EOF) {
			// A write like a dispatch answers with no body.
			w.WriteHeader(resp.StatusCode)
			log.Info("allowed", "status", resp.StatusCode)
			return
		} else if err != nil {
			refuse(http.StatusBadGateway, "GitHub's answer wasn't JSON")
			return
		}
		stripKeys(v, strip)
		w.WriteHeader(resp.StatusCode)
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(v)
		log.Info("allowed", "status", resp.StatusCode)
		return
	}
	w.WriteHeader(resp.StatusCode)
	flushCopy(w, w, resp.Body)
	log.Info("allowed", "status", resp.StatusCode)
}

// serveAnonymous sends a read hallpass doesn't cover to GitHub without the
// token, so GitHub shows only what anyone could fetch. When GitHub won't show
// it, or the policy denies anonymous reads, gh gets rest.Why.
func (s *Server) serveAnonymous(w http.ResponseWriter, r *http.Request, rest *policy.REST, log *slog.Logger, refuse func(int, string)) {
	if !s.Config.Anonymous(rest.Repo) {
		refuse(http.StatusForbidden, rest.Why)
		return
	}
	up, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.Config.API()+rest.Path, nil)
	if err != nil {
		refuse(http.StatusInternalServerError, err.Error())
		return
	}
	copyHeaders(up.Header, r.Header, "Accept", "User-Agent", "X-GitHub-Api-Version", "If-None-Match", "Time-Zone")
	// No Authorization header, and no noteRate: the anonymous limit is the
	// machine's address's, not the token's.
	resp, err := s.upstream().Do(up)
	if err != nil {
		refuse(http.StatusBadGateway, "couldn't reach GitHub: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 3 && resp.StatusCode != http.StatusNotModified {
		// gh can't follow a redirect itself: everything it sends comes to
		// this socket, which forwards only to api.github.com.
		resp.Body.Close()
		if resp, err = s.followStorage(r.Context(), resp.Header.Get("Location")); err != nil {
			refuse(http.StatusBadGateway, err.Error())
			return
		}
		defer resp.Body.Close()
	}
	switch {
	case resp.Header.Get("X-RateLimit-Remaining") == "0" && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests):
		reset, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
		refuse(http.StatusTooManyRequests, "GitHub's limit on requests without a token is used up until "+time.Unix(reset, 0).Format("15:04")+". "+rest.Why)
		return
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		refuse(http.StatusForbidden, "Without a token, GitHub answered "+resp.Status+". "+rest.Why)
		return
	}
	copyHeaders(w.Header(), resp.Header, "Content-Type", "Content-Encoding", "ETag", "Last-Modified", "Link",
		"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Used", "X-RateLimit-Resource",
		"X-GitHub-Request-Id", "Retry-After")
	w.WriteHeader(resp.StatusCode)
	flushCopy(w, w, resp.Body)
	log.Info("allowed", "status", resp.StatusCode)
}

// stripKeys deletes keys from every object in v, however deep.
func stripKeys(v any, keys []string) {
	switch v := v.(type) {
	case map[string]any:
		for _, k := range keys {
			delete(v, k)
		}
		for _, c := range v {
			stripKeys(c, keys)
		}
	case []any:
		for _, c := range v {
			stripKeys(c, keys)
		}
	}
}

// checkGraphQL checks the repos and node IDs a GraphQL request names. It
// returns a refusal message, or "".
func (s *Server) checkGraphQL(ctx context.Context, g *policy.GraphQL) string {
	allowed := func(repo github.Repo) (bool, op.Set, bool) {
		rule, ok := s.Config.Allowed(repo)
		return rule.Write, rule.Ops, ok
	}
	for _, r := range g.Repos {
		if _, _, ok := allowed(r); !ok {
			return r.String() + " isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow " + r.String()
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
// whether the token's user wrote it. It asks on every request: a cached
// answer would outlive a repo transfer.
func (s *Server) resolve(ctx context.Context, ids []string) (map[string]policy.Node, error) {
	out := map[string]policy.Node{}
	b, _ := json.Marshal(map[string]any{"query": resolveQuery, "variables": map[string]any{"ids": ids}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.API()+"/graphql", bytes.NewReader(b))
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
	if len(r.Data.Nodes) != len(ids) {
		return nil, errors.New("GitHub returned the wrong number of nodes")
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
		out[ids[i]] = policy.Node{Type: n.Typename, Repo: repo, Authored: n.ViewerDidAuthor} //nolint:gosec // the length check above makes len(ids) == len(r.Data.Nodes)
	}
	return out, nil
}

// authored reports whether the token's user wrote the object at path, and
// whether it's a PR, which GitHub also serves on the issues routes.
func (s *Server) authored(ctx context.Context, path string) (ok, isPR bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Config.API()+path, nil)
	if err != nil {
		return false, false, err
	}
	req.Header.Set("Authorization", "token "+s.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "hallpass")
	resp, err := s.upstream().Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, false, errors.New("GitHub answered " + resp.Status)
	}
	var obj struct {
		User struct{ Login string } `json:"user"`
		// An issue that is a PR has a pull_request object.
		PullRequest *struct{} `json:"pull_request"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&obj); err != nil {
		return false, false, err
	}
	login := ""
	if s.Config.Token != nil {
		login = s.Config.Token.Login
	}
	return login != "" && strings.EqualFold(obj.User.Login, login), obj.PullRequest != nil, nil
}

// storageHosts are where GitHub redirects downloads of run logs and
// artifacts. The URLs are signed, so they need no token.
// codeload serves the tarballs and zipballs an anonymous read redirects to.
var storageHosts = []string{".actions.githubusercontent.com", ".blob.core.windows.net", "objects.githubusercontent.com", "codeload.github.com"}

func (s *Server) followStorage(ctx context.Context, loc string) (*http.Response, error) {
	u, err := url.Parse(loc)
	if err != nil || u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return nil, errors.New("GitHub redirected somewhere hallpass doesn't follow")
	}
	ok := false
	for _, h := range storageHosts {
		ok = ok || strings.HasSuffix(u.Hostname(), h) || u.Hostname() == strings.TrimPrefix(h, ".")
	}
	// The slash keeps out hosts that start with the API's, like
	// api.github.com.evil.example and api.github.com@evil.example.
	if !ok && !strings.HasPrefix(loc, s.Config.API()+"/") {
		return nil, errors.New("GitHub redirected to " + u.Hostname() + ", which hallpass doesn't follow")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
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
