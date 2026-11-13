package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
)

// REST is a classified REST request to api.github.com.
type REST struct {
	// Repo is the repo the request touches, or nil for /user and the like.
	Repo  *github.Repo
	Write bool
	// Ops are the operations a write does. The repo's config must allow
	// each one.
	Ops []op.Op
	// Authored, when set, names the object the token's user must have
	// written: a GitHub API path like "/repos/o/r/pulls/7".
	Authored string
	// Path is the upstream path and query, rebuilt from the parse.
	Path string
	// Body is the re-encoded JSON body, or nil.
	Body []byte
	// Follow means the broker follows GitHub's redirect itself, to signed
	// storage URLs for logs and artifacts, without the token.
	Follow bool
	// Route names the rule, for the audit log.
	Route string
	// Strip names response fields the broker removes at any depth of a
	// JSON answer.
	Strip []string
	// Answer, when set, checks GitHub's decoded JSON answer to a GET. The
	// broker refuses the whole answer when it returns an error, and refuses
	// a successful answer that isn't JSON.
	Answer func(any) error
	// NeedsToken marks a read GitHub answers only with a token, so the
	// broker refuses it outside the allowlist instead of sending it
	// without one.
	NeedsToken bool
	// Anonymous marks a GET the allowlist and read tables don't cover and
	// no policy denies. The broker may send it without the token, so GitHub
	// shows only what anyone could fetch. Why is the refusal to give when
	// the broker can't.
	Anonymous bool
	Why       string
}

// anonymous marks r as a read to send without the token.
func (r *REST) anonymous(why string) *REST {
	r.Anonymous, r.Why, r.Route = true, why, "GET "+r.Path+" (anonymous)"
	return r
}

// reads are the repo paths agents may GET, under /repos/{owner}/{repo}. #
// is a number, * one name, and ** the rest of the path. Everything else,
// including secrets, variables, hooks, keys, alerts, and settings, is
// refused, and so is anything GitHub adds later. Literal segments match
// exactly, so a case variant GitHub might route the same way is refused.
var reads = []string{
	"",
	"branches", "branches/**", "tags", "languages", "contributors", "topics",
	"commits", "commits/**", "compare/**", "contents", "contents/**", "readme", "readme/**",
	"git/blobs/*", "git/trees/**", "git/commits/*", "git/tags/*", "git/ref/**", "git/refs", "git/refs/**", "git/matching-refs/**",
	"pulls", "pulls/#", "pulls/#/files", "pulls/#/commits", "pulls/#/comments", "pulls/#/reviews",
	"pulls/#/reviews/#", "pulls/#/reviews/#/comments", "pulls/#/requested_reviewers", "pulls/comments/#",
	// No issues/#/timeline: it carries the bodies of issues in other repos
	// that cross-reference this one.
	"issues", "issues/#", "issues/#/comments", "issues/#/events", "issues/#/labels",
	"issues/comments/#", "issues/events/#", "labels", "labels/*", "milestones", "milestones/#",
	"assignees", "assignees/*", "collaborators/*/permission",
	"check-runs/#", "check-runs/#/annotations", "check-suites/#", "check-suites/#/check-runs",
	"actions/runs", "actions/runs/#", "actions/runs/#/jobs", "actions/runs/#/attempts/#", "actions/runs/#/attempts/#/jobs",
	"actions/runs/#/artifacts", "actions/runs/#/logs", "actions/runs/#/attempts/#/logs",
	"actions/jobs/#", "actions/jobs/#/logs", "actions/artifacts", "actions/artifacts/#", "actions/artifacts/#/zip",
	"actions/workflows", "actions/workflows/*", "actions/workflows/*/runs",
	"releases", "releases/latest", "releases/#", "releases/tags/**",
}

// checkBuiltinRead refuses reads that match a pattern in reads but could reach
// past the repo: comparisons with a fork, and git objects
// named by an abbreviated SHA. A repo shares its object store with its fork
// network, so an abbreviated SHA could be guessed into a fork's objects.
func checkBuiltinRead(rest []string, query url.Values) error {
	switch {
	case match(rest, "compare/**"):
		spec := strings.Join(rest[1:], "/")
		if strings.Contains(spec, ":") {
			return errorf("hallpass only compares refs inside the repo, not with a fork (%s)", spec)
		}
		for _, side := range compareSides.Split(spec, -1) {
			if err := checkRev(side); err != nil {
				return err
			}
		}
	case match(rest, "commits/**"):
		if err := checkRevPath(rest[1:]); err != nil {
			return err
		}
	case len(rest) >= 3 && rest[0] == "git" && (rest[1] == "trees" || rest[1] == "commits" || rest[1] == "blobs" || rest[1] == "tags"):
		if err := checkRevPath(rest[2:]); err != nil {
			return err
		}
	}
	for _, k := range []string{"ref", "sha"} {
		if err := checkRev(query.Get(k)); err != nil {
			return err
		}
	}
	return nil
}

var (
	shortSHA     = regexp.MustCompile(`^[0-9a-fA-F]{4,39}$`)
	compareSides = regexp.MustCompile(`\.\.\.?`)
)

// describedSHA matches the end of what git describe prints, like
// v1.2-3-gabc1234. git reads the hex after -g as an abbreviated SHA and
// ignores what comes before it.
var describedSHA = regexp.MustCompile(`-g[0-9a-fA-F]{4,}$`)

// checkRev refuses an abbreviated SHA, and any revision expression, like
// abc1234~0 or x-1-gabc1234, since one can wrap an abbreviated SHA. Full
// SHAs and ref names pass: a ref name can't hold ~, ^, :, or @{. A ref
// whose name ends as git describe's output does, in -g and four or more
// hex digits, is refused too, since the broker can't tell the two apart.
func checkRev(rev string) error {
	if shortSHA.MatchString(rev) {
		return errorf("hallpass needs the full SHA, not %q, because GitHub resolves abbreviated ones across forks", rev)
	}
	return checkRevExpr(rev, rev)
}

// checkRevExpr refuses rev when part, its last segment or all of it, holds
// what makes a revision an expression.
func checkRevExpr(part, rev string) error {
	if strings.ContainsAny(part, "~^:") || strings.Contains(part, "@{") || describedSHA.MatchString(part) {
		return errorf("hallpass needs a full SHA or a ref name, not the expression %q, because GitHub resolves abbreviated SHAs across forks", rev)
	}
	return nil
}

// checkRevPath checks the revision that starts a route's remaining
// segments. A ref name may hold slashes, so the revision may run past the
// first segment, and where it ends depends on the route. So each later
// segment is checked as the end of an expression: a/b-1-gabc1234 wraps an
// abbreviated SHA as b-1-gabc1234 does.
func checkRevPath(segs []string) error {
	if err := checkRev(segs[0]); err != nil {
		return err
	}
	for i := 1; i < len(segs); i++ {
		if err := checkRevExpr(segs[i], strings.Join(segs[:i+1], "/")); err != nil {
			return err
		}
	}
	return nil
}

// unstripped are reads whose responses the broker can't parse and strip,
// because they're file contents (up to 100 MB) or redirects to storage. They
// carry no repo objects.
var unstripped = []string{"contents/**", "readme", "readme/**", "git/blobs/*"}

var (
	number = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	// name is a path segment like a workflow's file name, matched by *.
	name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
)

// ClassifyREST decides a REST request. target is the raw request target. g
// adds and removes read routes; nil means the built-in ones.
func ClassifyREST(method, target string, body []byte, g *Grants) (*REST, error) {
	if err := cleanTarget(target); err != nil {
		// gh writes a branch's ref with its slash encoded (heads%2Fname),
		// which cleanTarget refuses whatever the write is. Say why a ref
		// write can't go this way at all, not that the encoding is wrong.
		if refWrite(method, target) {
			return nil, errRefWrite
		}
		return nil, err
	}
	rawPath, rawQuery, _ := strings.Cut(target, "?")
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, errorf("malformed query string")
	}
	// The checks below read one value per key, and Encode forwards them
	// all, so a second value would reach GitHub unchecked.
	for k, v := range query {
		if len(v) > 1 {
			return nil, errorf("hallpass doesn't accept %q twice in a query string", k)
		}
	}
	segs := strings.Split(strings.TrimPrefix(rawPath, "/"), "/")
	r := &REST{Path: rawPath}
	if len(query) > 0 {
		r.Path += "?" + query.Encode()
	}

	switch {
	case method == "GET" && (rawPath == "/user" || rawPath == "/rate_limit"):
		r.Route = "GET " + rawPath
		return r, nil
	case method == "GET" && rawPath == "/search/issues":
		repo, err := SearchRepo(query.Get("q"))
		if err != nil {
			return r.anonymous(err.Error()), nil
		}
		r.Repo, r.Route, r.Answer = &repo, "GET /search/issues", issueAnswer(repo)
		return r, nil
	case method == "GET" && rawPath == "/search/code":
		// GitHub answers code search only with a token, so a query the
		// broker can't confine is refused, not sent without one.
		repo, err := CodeSearchRepo(query.Get("q"))
		if err != nil {
			return nil, err
		}
		if from := g.deniesContents(repo); from != "" {
			return nil, errorf("hallpass doesn't search code in %s: the policy for %s denies reading some of its files", repo, from)
		}
		r.Repo, r.Route, r.NeedsToken = &repo, "GET /search/code", true
		r.Strip, r.Answer = []string{"temp_clone_token"}, codeAnswer(repo)
		return r, nil
	case len(segs) < 3 || segs[0] != "repos":
		why := "hallpass doesn't allow " + method + " " + rawPath
		if method == "GET" {
			return r.anonymous(why), nil
		}
		return nil, errorf("%s", why)
	}
	repo, err := github.ParseRepo(segs[1] + "/" + segs[2])
	if err != nil || strings.HasSuffix(segs[2], ".git") {
		return nil, errorf("not a repo path: %s", rawPath)
	}
	r.Repo = &repo
	rest := segs[3:]
	if len(rest) > 0 && rest[len(rest)-1] == "" {
		return nil, errorf("hallpass doesn't accept a trailing slash")
	}
	base := "/repos/" + repo.Owner + "/" + repo.Name

	if method == "GET" {
		if floored(rest) {
			return nil, errorf("hallpass never allows reading %s: no policy opens secrets, settings, keys, hooks, or security findings", pattern(rest))
		}
		builtin := anyMatch(rest, reads)
		on, from := g.readOn(repo, rest, builtin)
		if !on {
			p := readPattern(rest)
			msg := "hallpass doesn't allow reading " + pattern(rest)
			if len(rest) > 0 && CheckRead(p) == nil {
				why := "Reads are limited to code, PRs, issues, checks, and Actions runs"
				if from != "default" {
					why = "The policy for " + from + " denies it"
				}
				msg = fmt.Sprintf("hallpass doesn't allow reading %s in %s. %s. To allow it: sudo /opt/hallpass/bin/hallpass policy allow read:%s --repo %s", pattern(rest), repo, why, p, repo)
			}
			// A read the tables don't cover can go without the token. One a
			// policy denies can't, even where GitHub would show it to anyone.
			if from == "default" {
				return r.anonymous(msg), nil
			}
			return nil, errorf("%s", msg)
		}
		if builtin {
			if err := checkBuiltinRead(rest, query); err != nil {
				return nil, err
			}
			r.Follow = match(rest, "actions/runs/#/logs") || match(rest, "actions/runs/#/attempts/#/logs") ||
				match(rest, "actions/jobs/#/logs") || match(rest, "actions/artifacts/#/zip")
		}
		if !r.Follow && !slices.ContainsFunc(unstripped, func(p string) bool { return match(rest, p) }) {
			// A private repo object carries a temporary clone credential,
			// at the top of /repos/o/r and nested in parent, source, and
			// PRs' base.repo and head.repo.
			r.Strip = []string{"temp_clone_token"}
		}
		r.Route = "GET " + pattern(rest)
		if from != "default" {
			r.Route += " (allowed by " + from + ")"
		}
		return r, nil
	}

	for _, wr := range restWrites(repo, rest) {
		if wr.method != method || !match(rest, wr.path) {
			continue
		}
		if len(query) > 0 {
			return nil, errorf("hallpass doesn't accept a query string on %s", wr.path)
		}
		if wr.op == "" {
			return nil, errorf("hallpass has no operation for %s %s, so it refuses it", method, wr.path)
		}
		r.Write, r.Route, r.Ops = true, method+" "+wr.path, []op.Op{wr.op}
		// A PR a write returns carries base.repo and head.repo, which hold
		// the same clone credential as a read.
		r.Strip = []string{"temp_clone_token"}
		if wr.authored != "" {
			r.Authored = base + wr.authored
		}
		if wr.empty && len(bytes.TrimSpace(body)) == 0 {
			return r, nil
		}
		keys := slices.Clone(wr.keys)
		for k := range wr.opKeys {
			keys = append(keys, k)
		}
		b, err := strictJSON(body, keys)
		if err != nil {
			return nil, err
		}
		for k := range b {
			if o, ok := wr.opKeys[k]; ok {
				r.Ops = append(r.Ops, o)
			}
		}
		if wr.check != nil {
			o, err := wr.check(b)
			if err != nil {
				return nil, err
			}
			if o != "" {
				r.Ops = append(r.Ops, o)
			}
		}
		// Every string, including the comments in a review.
		if err := CheckStrings(b); err != nil {
			return nil, err
		}
		if r.Body, err = json.Marshal(b); err != nil {
			return nil, err
		}
		return r, nil
	}
	if refWrite(method, target) {
		return nil, errRefWrite
	}
	return nil, errorf("hallpass doesn't allow %s %s", method, pattern(rest))
}

// refWriteTarget is a request target under a repo's git/refs.
var refWriteTarget = regexp.MustCompile(`^/repos/[^/?]+/[^/?]+/git/refs(/|\?|$)`)

// refWrite reports whether a request would create, move, or delete a ref
// through the REST API, which hallpass never allows: branch changes go through
// git push, where it checks each one against the default branch, protected
// branches, and the branches agents pushed (see CheckPush).
func refWrite(method, target string) bool {
	return method != "GET" && refWriteTarget.MatchString(target)
}

var errRefWrite = errorf("hallpass doesn't let agents change refs through GitHub's API; branch changes go through git push, where hallpass checks them. " +
	"To delete a branch an agent pushed: git push origin --delete BRANCH. " +
	"To have GitHub delete a PR's branch when it merges, turn on automatically deleting head branches in the repo's settings")

// reviewEvent names the operation a review's event needs beyond a comment.
// Without an event, GitHub leaves the review pending.
func reviewEvent(b map[string]any) (op.Op, error) {
	e, ok := b["event"]
	if !ok {
		return "", nil
	}
	return verdict(e)
}

// verdict maps a review event, from REST or GraphQL, to its operation.
func verdict(event any) (op.Op, error) {
	switch event {
	case "COMMENT":
		return "", nil
	case "APPROVE", "REQUEST_CHANGES":
		return op.ReviewVerdict, nil
	}
	return "", errorf("hallpass doesn't know the review event %v", event)
}

// match compares path segments to a pattern where # is a number and * is a
// name.
func match(segs []string, pat string) bool {
	if pat == "" {
		return len(segs) == 0
	}
	p := strings.Split(pat, "/")
	if p[len(p)-1] == "**" {
		// The rest of the path, at least one segment.
		if len(segs) < len(p) {
			return false
		}
		segs = segs[:len(p)-1]
		p = p[:len(p)-1]
	}
	if len(p) != len(segs) {
		return false
	}
	for i := range p {
		switch p[i] {
		case "#":
			if !number.MatchString(segs[i]) {
				return false
			}
		case "*":
			if !name.MatchString(segs[i]) {
				return false
			}
		default:
			if p[i] != segs[i] {
				return false
			}
		}
	}
	return true
}

// pattern names a path for the audit log, with numbers replaced by #.
func pattern(segs []string) string {
	out := slices.Clone(segs)
	for i, s := range out {
		if number.MatchString(s) {
			out[i] = "#"
		}
	}
	return "repos/{repo}/" + strings.Join(out, "/")
}

// strictJSON decodes a JSON object with only the given keys.
func strictJSON(body []byte, keys []string) (map[string]any, error) {
	if err := strictObject(body, keys); err != nil {
		return nil, err
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, errorf("malformed JSON")
	}
	return m, nil
}

type restWrite struct {
	method, path string
	op           op.Op
	keys         []string
	// opKeys are keys that also need an operation of their own.
	opKeys   map[string]op.Op
	authored string // "" or the API path suffix to look up
	// check refuses a body, or names an operation it also needs.
	check func(map[string]any) (op.Op, error)
	// empty accepts a request without a body, as gh sends for reruns.
	empty bool
}

// restWrites is every REST write agents may make, each under the operation
// the config must allow. rest is the request's path after /repos/OWNER/NAME,
// which the authored lookups need.
func restWrites(repo github.Repo, rest []string) []restWrite {
	n := func(i int) string {
		if i < len(rest) {
			return rest[i]
		}
		return ""
	}
	issueKeys := map[string]op.Op{"assignees": op.Assign, "labels": op.Labels}
	return []restWrite{
		{method: "POST", path: "pulls", op: op.PRCreate, keys: []string{"title", "body", "head", "base", "draft", "maintainer_can_modify"}, check: func(b map[string]any) (op.Op, error) {
			if h, _ := b["head"].(string); strings.Contains(h, ":") && !strings.EqualFold(strings.SplitN(h, ":", 2)[0], repo.Owner) {
				return "", errorf("agents may only open PRs from a branch in the same repo")
			}
			return "", nil
		}},
		{method: "POST", path: "issues", op: op.IssueCreate, keys: []string{"title", "body"}, opKeys: issueKeys},
		{method: "POST", path: "issues/#/comments", op: op.Comment, keys: []string{"body"}},
		{method: "POST", path: "pulls/#/comments", op: op.ReviewComment, keys: []string{"body", "commit_id", "path", "line", "side", "start_line", "start_side", "subject_type", "in_reply_to", "position"}},
		{method: "POST", path: "pulls/#/comments/#/replies", op: op.ReviewComment, keys: []string{"body"}},
		{method: "POST", path: "pulls/#/reviews", op: op.ReviewComment, keys: []string{"body", "event", "comments", "commit_id"}, check: reviewEvent},
		{method: "POST", path: "pulls/#/reviews/#/events", op: op.ReviewComment, keys: []string{"body", "event"}, authored: "/pulls/" + n(1) + "/reviews/" + n(3), check: reviewEvent},
		{method: "POST", path: "pulls/#/requested_reviewers", op: op.PRReviewers, keys: []string{"reviewers"}, authored: "/pulls/" + n(1)},
		{method: "PATCH", path: "pulls/#", op: op.PREdit, keys: []string{"title", "body", "state", "base", "maintainer_can_modify"}, authored: "/pulls/" + n(1)},
		{method: "PATCH", path: "issues/#", op: op.IssueEdit, keys: []string{"title", "body", "state", "state_reason"}, opKeys: issueKeys, authored: "/issues/" + n(1)},
		{method: "PATCH", path: "issues/comments/#", op: op.Comment, keys: []string{"body"}, authored: "/issues/comments/" + n(2)},
		{method: "PATCH", path: "pulls/comments/#", op: op.ReviewComment, keys: []string{"body"}, authored: "/pulls/comments/" + n(2)},

		{method: "POST", path: "issues/#/labels", op: op.Labels, keys: []string{"labels"}},
		{method: "PUT", path: "pulls/#/merge", op: op.PRMerge, keys: []string{"commit_title", "commit_message", "sha", "merge_method"}, empty: true},
		{method: "POST", path: "actions/runs/#/rerun", op: op.WorkflowRerun, keys: []string{"enable_debug_logging"}, empty: true},
		{method: "POST", path: "actions/runs/#/rerun-failed-jobs", op: op.WorkflowRerun, keys: []string{"enable_debug_logging"}, empty: true},
		{method: "POST", path: "actions/jobs/#/rerun", op: op.WorkflowRerun, keys: []string{"enable_debug_logging"}, empty: true},
		{method: "POST", path: "actions/workflows/*/dispatches", op: op.WorkflowDispatch, keys: []string{"ref", "inputs"}},
	}
}
