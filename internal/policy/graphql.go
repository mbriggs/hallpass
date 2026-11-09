package policy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/formatter"
	"github.com/vektah/gqlparser/v2/validator"
	"github.com/vektah/gqlparser/v2/validator/rules"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
)

//go:embed schema/github.graphql
var schemaSDL string

var (
	schemaOnce sync.Once
	schema     *ast.Schema
	errSchema  error
)

// Schema is GitHub's public GraphQL schema, embedded at build time.
func Schema() (*ast.Schema, error) {
	schemaOnce.Do(func() {
		schema, errSchema = gqlparser.LoadSchema(&ast.Source{Name: "github.graphql", Input: schemaSDL})
	})
	return schema, errSchema
}

var (
	rulesOnce sync.Once
	rulesSet  *rules.Rules
)

// queryRules are gqlparser's standard checks, less the overlapping-fields
// rule: gh sends queries that select a field twice with different
// nullability, which GitHub accepts. The walker checks every selection
// either way.
func queryRules() *rules.Rules {
	rulesOnce.Do(func() {
		rulesSet = rules.NewDefaultRules()
		rulesSet.RemoveRule("OverlappingFieldsCanBeMerged")
	})
	return rulesSet
}

// NodeUse is a node ID a request names. The broker resolves it, then checks
// it with Check.
type NodeUse struct {
	ID string
	// Types are the GraphQL types the ID may resolve to.
	Types []string
	Write bool
	// Ops are the operations a mutation does to the node. Its repo's config
	// must allow each one.
	Ops []op.Op
	// Authored requires that the token's user wrote the object.
	Authored bool
	// Where names the argument, for refusal messages.
	Where string
}

// Node is what the broker learned about a node ID.
type Node struct {
	Type     string
	Repo     github.Repo
	Authored bool
}

// GraphQL is a classified GraphQL request.
type GraphQL struct {
	Mutation bool
	// Fields names the root fields, for the audit log.
	Fields []string
	// Repos are the repos a read names directly. Writes name what they
	// change by node ID.
	Repos []github.Repo
	Nodes []NodeUse
	// Body is the request to send GitHub: the checked document printed from
	// the broker's own parse, and the coerced variables.
	Body []byte
}

// ClassifyGraphQL parses, validates, and walks a GraphQL request. It refuses
// anything that could read outside the repos the request names, or write
// anything outside the mutation table. g adds and removes fields an
// identity read may see; nil means the built-in ones.
func ClassifyGraphQL(body []byte, g *Grants) (*GraphQL, error) {
	s, err := Schema()
	if err != nil {
		return nil, err
	}
	var req struct {
		Query         string         `json:"query"`
		Variables     map[string]any `json:"variables"`
		OperationName string         `json:"operationName"`
	}
	if err := strictObject(body, []string{"query", "variables", "operationName"}); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		return nil, errorf("malformed GraphQL request")
	}
	doc, errs := gqlparser.LoadQueryWithRules(s, req.Query, queryRules())
	if len(errs) > 0 {
		return nil, errorf("hallpass couldn't check this GraphQL request against its copy of GitHub's schema: %s", errs[0].Message)
	}
	if len(doc.Operations) != 1 {
		return nil, errorf("hallpass accepts one GraphQL operation per request")
	}
	op := doc.Operations[0]
	if req.OperationName != "" && req.OperationName != op.Name {
		return nil, errorf("operationName doesn't match the operation")
	}
	vars, verr := validator.VariableValues(s, op, normalizeNumbers(req.Variables))
	if verr != nil {
		return nil, errorf("GraphQL variables: %v", verr)
	}

	w := &walker{schema: s, vars: vars, g: &GraphQL{}, grants: g}
	switch op.Operation {
	case ast.Query:
		err = w.queryRoot(op.SelectionSet)
	case ast.Mutation:
		w.g.Mutation = true
		err = w.mutationRoot(op.SelectionSet)
	default:
		err = errorf("hallpass doesn't forward GraphQL subscriptions")
	}
	if err != nil {
		return nil, err
	}

	var printed bytes.Buffer
	formatter.NewFormatter(&printed).FormatQueryDocument(doc)
	out := map[string]any{"query": printed.String()}
	if len(vars) > 0 {
		out["variables"] = vars
	}
	if op.Name != "" {
		out["operationName"] = op.Name
	}
	if w.g.Body, err = json.Marshal(out); err != nil {
		return nil, err
	}
	return w.g, nil
}

type view int

const (
	full     view = iota // in a repo the request named
	identity             // possibly elsewhere: names and IDs only
)

type walker struct {
	schema *ast.Schema
	vars   map[string]any
	g      *GraphQL
	grants *Grants
	fields int
}

const (
	maxDepth  = 25
	maxFields = 5000
)

func (w *walker) queryRoot(set ast.SelectionSet) error {
	return w.eachField(set, 0, func(f *ast.Field) error {
		w.g.Fields = append(w.g.Fields, f.Name)
		args := f.ArgumentMap(w.vars)
		switch f.Name {
		case "__typename", "__type", "__schema", "rateLimit":
			// The schema is public, and rate limits say nothing about repos.
			return nil
		case "repository":
			r, err := github.ParseRepo(fmt.Sprint(args["owner"]) + "/" + fmt.Sprint(args["name"]))
			if err != nil {
				return errorf("repository(...): %v", err)
			}
			if err := noRenames(f); err != nil {
				return err
			}
			w.g.Repos = append(w.g.Repos, r)
			return w.selections(f, full, 1)
		case "node", "nodes":
			ids := args["ids"]
			if f.Name == "node" {
				ids = []any{args["id"]}
			}
			list, _ := ids.([]any)
			if len(list) == 0 || len(list) > 100 {
				return errorf("node lookups need 1 to 100 IDs")
			}
			for _, id := range list {
				s, ok := id.(string)
				if !ok || s == "" {
					return errorf("node lookups need string IDs")
				}
				w.g.Nodes = append(w.g.Nodes, NodeUse{ID: s, Types: repoContentTypes(w.schema), Where: f.Name})
			}
			return w.selections(f, full, 1)
		case "viewer":
			return w.selections(f, identity, 1)
		case "search":
			// GitHub ignores repo: in user and repo searches, so only issue
			// searches stay inside the repo.
			if args["type"] != "ISSUE" {
				return errorf("hallpass only allows GraphQL searches of type ISSUE")
			}
			r, err := SearchRepo(fmt.Sprint(args["query"]))
			if err != nil {
				return err
			}
			w.g.Repos = append(w.g.Repos, r)
			return w.selections(f, full, 1)
		}
		return errorf("hallpass doesn't allow the GraphQL query field %s", f.Name)
	})
}

func (w *walker) mutationRoot(set ast.SelectionSet) error {
	return w.eachField(set, 0, func(f *ast.Field) error {
		w.g.Fields = append(w.g.Fields, f.Name)
		m, ok := mutations[f.Name]
		if !ok {
			return errorf("hallpass doesn't allow the GraphQL mutation %s", f.Name)
		}
		input, _ := f.ArgumentMap(w.vars)["input"].(map[string]any)
		if input == nil {
			return errorf("%s needs an input", f.Name)
		}
		var ops []op.Op
		if m.op != "" {
			ops = append(ops, m.op)
		}
		for k := range input {
			if o, ok := m.opFields[k]; ok {
				ops = append(ops, o)
				continue
			}
			if !slices.Contains(m.fields, k) && k != "clientMutationId" {
				return errorf("hallpass doesn't allow %s with %s", f.Name, k)
			}
		}
		if m.check != nil {
			o, err := m.check(input)
			if err != nil {
				return err
			}
			if o != "" {
				ops = append(ops, o)
			}
		}
		bound := false
		for _, b := range m.binds {
			id, ok := input[b.field].(string)
			if !ok {
				continue
			}
			bound = true
			w.g.Nodes = append(w.g.Nodes, NodeUse{ID: id, Types: b.types, Write: true, Ops: ops, Authored: b.authored, Where: f.Name + "." + b.field})
		}
		if !bound {
			return errorf("%s doesn't name what it changes", f.Name)
		}
		// Every string, including review threads' bodies, since bots act on
		// review comments too.
		if err := CheckStrings(input); err != nil {
			return err
		}
		// The payload is a read of what the mutation changed.
		return w.selections(f, full, 1)
	})
}

// eachField calls fn for each field in set, following fragments.
func (w *walker) eachField(set ast.SelectionSet, depth int, fn func(*ast.Field) error) error {
	if depth > maxDepth {
		return errorf("GraphQL request is nested too deeply")
	}
	for _, sel := range set {
		if err := checkDirectives(sel); err != nil {
			return err
		}
		switch s := sel.(type) {
		case *ast.Field:
			w.fields++
			if w.fields > maxFields {
				return errorf("GraphQL request selects too many fields")
			}
			if err := fn(s); err != nil {
				return err
			}
		case *ast.InlineFragment:
			if err := w.eachField(s.SelectionSet, depth+1, fn); err != nil {
				return err
			}
		case *ast.FragmentSpread:
			if s.Definition == nil {
				return errorf("unknown fragment %s", s.Name)
			}
			if err := w.eachField(s.Definition.SelectionSet, depth+1, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkDirectives(sel ast.Selection) error {
	var ds ast.DirectiveList
	switch s := sel.(type) {
	case *ast.Field:
		ds = s.Directives
	case *ast.InlineFragment:
		ds = s.Directives
	case *ast.FragmentSpread:
		ds = s.Directives
	}
	for _, d := range ds {
		// Both branches of @include and @skip get checked, whatever their
		// condition.
		if d.Name != "include" && d.Name != "skip" {
			return errorf("hallpass doesn't forward the @%s directive", d.Name)
		}
	}
	return nil
}

// selections walks the fields under f, whose own view is v.
func (w *walker) selections(f *ast.Field, v view, depth int) error {
	if f.Definition == nil {
		return nil
	}
	return w.eachField(f.SelectionSet, depth, func(c *ast.Field) error {
		if c.Name == "__typename" || c.Definition == nil {
			return nil
		}
		child := w.schema.Types[c.Definition.Type.Name()]
		if child == nil {
			return errorf("unknown type for %s", c.Name)
		}
		owner := c.ObjectDefinition.Name
		if deniedFields[owner+"."+c.Name] {
			return errorf("hallpass doesn't let agents read %s.%s", owner, c.Name)
		}
		if owner == "Repository" && c.Name == "object" {
			args := c.ArgumentMap(w.vars)
			if expr, ok := args["expression"].(string); ok {
				// git reads ":/text" and ":0:path" with nothing before the
				// colon, so a revision is required there.
				rev, _, _ := strings.Cut(expr, ":")
				if rev == "" {
					return errorf("hallpass needs a full SHA or a ref name before the colon in %q", expr)
				}
				if err := checkRev(rev); err != nil {
					return err
				}
			}
			if oid, ok := args["oid"].(string); ok {
				if err := checkRev(oid); err != nil {
					return err
				}
			}
		}
		if child.Kind == ast.Scalar || child.Kind == ast.Enum {
			if v == identity && !w.identityField(owner, c.Name) {
				key := owner + "." + c.Name
				if CheckField(key) != nil {
					return errorf("hallpass doesn't allow reading %s here, because it may be outside the repo you named", key)
				}
				return errorf("hallpass doesn't allow reading %s here, because it may be outside the repo you named. To allow it everywhere: sudo /opt/hallpass/bin/hallpass policy allow field:%s", key, key)
			}
			return nil
		}
		next, err := w.edgeView(v, owner, c.Name, child, len(c.Definition.Arguments) > 0)
		if err != nil {
			return err
		}
		return w.selections(c, next, depth+1)
	})
}

// edgeView decides the view below an object-typed field. lookup is set when
// the field takes arguments, like User.repository(name:), which finds an
// object rather than following one.
func (w *walker) edgeView(v view, owner, field string, child *ast.Definition, lookup bool) (view, error) {
	if v == identity {
		// Identity reads may only hop to an owner's or repo's name, or list the
		// members of a connection they were already given, like a PR's
		// assignees. They can't enter a new connection. The repo an object
		// belongs to, like a sub-issue's parent's, is an identity read too,
		// but not a repo looked up by name.
		if (field == "owner" || field == "organization" || field == "repository") && !isConnection(child) && !lookup {
			return identity, nil
		}
		// The default branch's name, for gh pr create on a fork. Its
		// target and history are a further hop, which this refuses.
		if owner == "Repository" && field == "defaultBranchRef" {
			return identity, nil
		}
		if isWrapper(owner) && (field == "nodes" || field == "edges" || field == "node" || field == "pageInfo") {
			return identity, nil
		}
		return identity, errorf("hallpass doesn't allow reading %s.%s here, because it may be outside the repo you named", owner, field)
	}
	// Connections and edges carry the view of the field that led to them.
	if isWrapper(owner) && (field == "nodes" || field == "edges" || field == "node" || field == "pageInfo") {
		return v, nil
	}
	target := unwrap(w.schema, child)
	switch {
	case w.isPivot(target):
		return identity, nil
	case w.isRepoContent(target):
		// A mutation's payload is what it changed, in the repo it was bound
		// to.
		if sameRepo[owner+"."+field] || strings.HasSuffix(owner, "Payload") {
			return full, nil
		}
		return identity, nil
	}
	return full, nil
}

func isWrapper(name string) bool {
	return strings.HasSuffix(name, "Connection") || strings.HasSuffix(name, "Edge")
}

func isConnection(d *ast.Definition) bool { return isWrapper(d.Name) }

// unwrap finds the node type behind a connection or edge type.
func unwrap(s *ast.Schema, d *ast.Definition) *ast.Definition {
	for range 3 {
		if !isWrapper(d.Name) {
			return d
		}
		f := d.Fields.ForName("nodes")
		if f == nil {
			f = d.Fields.ForName("node")
		}
		if f == nil {
			return d
		}
		d = s.Types[f.Type.Name()]
	}
	return d
}

// pivotTypes are objects that live outside any one repo: accounts, repos
// themselves, and projects. Reads reaching them get names and IDs only.
var pivotTypes = map[string]bool{
	"Repository": true, "User": true, "Organization": true, "Bot": true, "Mannequin": true,
	"Team": true, "Enterprise": true, "EnterpriseUserAccount": true, "App": true,
	"ProjectV2": true, "Project": true,
}

func (w *walker) isPivot(d *ast.Definition) bool {
	for _, p := range w.possible(d) {
		if pivotTypes[p] {
			return true
		}
	}
	return false
}

// isRepoContent reports whether d, or a type it may be, belongs to a repo.
func (w *walker) isRepoContent(d *ast.Definition) bool {
	for _, p := range w.possible(d) {
		if t := w.schema.Types[p]; t != nil && t.Fields.ForName("repository") != nil {
			return true
		}
	}
	return false
}

func (w *walker) possible(d *ast.Definition) []string {
	if d.Kind == ast.Object {
		return []string{d.Name}
	}
	var out []string
	for _, p := range w.schema.GetPossibleTypes(d) {
		out = append(out, p.Name)
	}
	return out
}

var contentOnce sync.Once
var contentTypes []string

// repoContentTypes lists every object type that's in a repo: what a node
// ID in a read may resolve to. A repository field that takes arguments,
// like User.repository(name:), looks up any repo, so it doesn't count.
func repoContentTypes(s *ast.Schema) []string {
	contentOnce.Do(func() {
		for name, t := range s.Types {
			f := t.Fields.ForName("repository")
			if t.Kind == ast.Object && (name == "Repository" || f != nil && len(f.Arguments) == 0) {
				contentTypes = append(contentTypes, name)
			}
		}
		slices.Sort(contentTypes)
	})
	return contentTypes
}

// identityScalars are what a read may see of an object that may be outside
// the named repo.
var identityScalars = map[string]bool{
	"id": true, "databaseId": true, "login": true, "name": true, "nameWithOwner": true,
	"url": true, "resourcePath": true, "avatarUrl": true, "slug": true, "isPrivate": true,
	"isFork": true, "isArchived": true, "number": true, "state": true, "title": true,
	"totalCount": true, "hasNextPage": true, "hasPreviousPage": true, "endCursor": true, "startCursor": true,
}

// identityField reports whether an identity read may see owner.name: the
// config's setting if it has one, else the built-in tables.
func (w *walker) identityField(owner, name string) bool {
	if on, set := w.grants.fieldOn(owner + "." + name); set {
		return on
	}
	return identityScalars[name] || identityFields[owner+"."+name]
}

// identityFields are further fields of one type that a read may see of an
// object that may be outside the named repo, each because gh needs it and
// it says nothing about a repo's code, issues, or PRs. Keep this to what gh
// asks for.
var identityFields = map[string]bool{
	// gh pr create reads these of the repo's parent, which for a fork can
	// be a repo the allowlist doesn't cover. They're settings and a
	// one-line description.
	"Repository.hasIssuesEnabled": true,
	"Repository.hasWikiEnabled":   true,
	"Repository.viewerPermission": true,
	"Repository.description":      true,
	// gh pr status reads it through PullRequest.baseRef.
	"BranchProtectionRule.requiresStrictStatusChecks": true,
}

// deniedFields are fields agents can't read even in an allowed repo.
var deniedFields = map[string]bool{
	// A temporary credential for cloning the private repo.
	"Repository.tempCloneToken": true,
	// Settings, which the README says agents can't read.
	"Repository.deployKeys":            true,
	"Repository.rulesets":              true,
	"Repository.ruleset":               true,
	"Repository.codeowners":            true,
	"Repository.interactionAbility":    true,
	"Repository.branchProtectionRules": true,
	// REST's read floor has properties, and environments' protection
	// rules are settings. Many types lead to an environment, so the rules
	// are denied on Environment itself.
	"Repository.repositoryCustomPropertyValue":  true,
	"Repository.repositoryCustomPropertyValues": true,
	"Environment.protectionRules":               true,
}

// noRenames pins repository(owner, name) to the repo of that name.
// followRenames defaults to true, so if an allowed repo was renamed or
// transferred, GitHub would answer for the repo it is now, which the
// allowlist may not cover.
func noRenames(f *ast.Field) error {
	if a := f.Arguments.ForName("followRenames"); a != nil {
		if a.Value.Kind != ast.BooleanValue || a.Value.Raw != "false" {
			return errorf("hallpass only allows repository(followRenames: false)")
		}
		return nil
	}
	f.Arguments = append(f.Arguments, &ast.Argument{Name: "followRenames", Value: &ast.Value{Kind: ast.BooleanValue, Raw: "false"}})
	return nil
}

// sameRepo lists edges GitHub guarantees stay inside the parent's repo. A
// repo-content field missing from here is read with the identity view.
var sameRepo = map[string]bool{}

func init() {
	for e := range strings.FieldsSeq(`
		Repository.pullRequest Repository.pullRequests Repository.issue Repository.issues
		Repository.issueOrPullRequest Repository.object Repository.ref Repository.refs
		Repository.defaultBranchRef Repository.labels Repository.label Repository.milestones
		Repository.milestone Repository.releases Repository.release Repository.latestRelease
		PullRequest.commits PullRequest.comments PullRequest.reviews PullRequest.latestReviews
		PullRequest.latestOpinionatedReviews PullRequest.reviewThreads PullRequest.reviewRequests
		PullRequest.baseRef PullRequest.mergeCommit PullRequest.potentialMergeCommit
		PullRequest.labels PullRequest.milestone PullRequest.timelineItems PullRequest.projectItems
		PullRequest.files
		PullRequestCommit.commit PullRequestCommit.pullRequest
		PullRequestReview.comments PullRequestReview.commit PullRequestReview.pullRequest
		PullRequestReviewThread.comments PullRequestReviewThread.pullRequest
		PullRequestReviewComment.pullRequest PullRequestReviewComment.pullRequestReview
		PullRequestReviewComment.commit PullRequestReviewComment.originalCommit
		Issue.comments Issue.labels Issue.milestone Issue.timelineItems Issue.projectItems
		IssueComment.issue IssueComment.pullRequest
		Commit.statusCheckRollup Commit.status Commit.checkSuites Commit.parents Commit.history
		Commit.tree Commit.file
		StatusCheckRollup.contexts StatusCheckRollup.commit Status.contexts Status.commit
		StatusContext.commit
		CheckSuite.checkRuns CheckSuite.commit CheckSuite.workflowRun
		CheckRun.checkSuite WorkflowRun.checkSuite WorkflowRun.workflow
		Ref.target Tree.entries TreeEntry.object
		Label.issues Label.pullRequests Milestone.issues Milestone.pullRequests
		ProjectV2Item.fieldValueByName ProjectV2Item.fieldValues
	`) {
		sameRepo[e] = true
	}
}

// SearchRepo reads the one repo a search query is confined to. It refuses
// queries that could reach further: boolean operators, more than one repo,
// or owner-wide qualifiers.
func SearchRepo(q string) (github.Repo, error) {
	// GitHub reads a quoted phrase as one term, so a repo: qualifier inside
	// quotes isn't one. Refusing quotes keeps the broker and GitHub reading
	// the query the same way.
	if strings.ContainsAny(q, "\"'\\") {
		return github.Repo{}, errorf("hallpass doesn't allow quotes in searches")
	}
	var repo string
	for tok := range strings.FieldsSeq(strings.NewReplacer("(", " ", ")", " ").Replace(q)) {
		low := strings.ToLower(tok)
		switch {
		case low == "or" || low == "and" || low == "not":
			return github.Repo{}, errorf("hallpass doesn't allow boolean operators in searches")
		case strings.HasPrefix(low, "repo:"):
			if repo != "" {
				return github.Repo{}, errorf("hallpass allows one repo: qualifier per search")
			}
			repo = tok[len("repo:"):]
		case strings.HasPrefix(low, "org:"), strings.HasPrefix(low, "user:"),
			strings.HasPrefix(low, "owner:"), strings.HasPrefix(low, "-repo:"):
			return github.Repo{}, errorf("hallpass searches only within one repo, so it doesn't allow %s", tok)
		}
	}
	if repo == "" {
		return github.Repo{}, errorf("hallpass searches only within one repo; add repo:OWNER/NAME")
	}
	return github.ParseRepo(repo)
}

type bind struct {
	field    string
	types    []string
	authored bool
}

type mutation struct {
	op     op.Op
	fields []string
	// opFields are input fields that also need an operation of their own.
	opFields map[string]op.Op
	binds    []bind
	// check refuses an input, or names an operation it also needs.
	check func(input map[string]any) (op.Op, error)
}

var (
	pr       = []string{"PullRequest"}
	issue    = []string{"Issue"}
	issueOr  = []string{"Issue", "PullRequest"}
	repoType = []string{"Repository"}

	assignLabel = map[string]op.Op{"assigneeIds": op.Assign, "labelIds": op.Labels}
)

func reviewVerdict(input map[string]any) (op.Op, error) {
	e, ok := input["event"]
	if !ok {
		return "", nil
	}
	return verdict(e)
}

// mutations is everything agents may change through GraphQL, each under
// the operation the config must allow. Anything else, including ref writes,
// settings, and projects, is refused.
var mutations = map[string]mutation{
	"createPullRequest": {
		op:     op.PRCreate,
		fields: []string{"repositoryId", "baseRefName", "headRefName", "headRepositoryId", "title", "body", "draft", "maintainerCanModify"},
		binds:  []bind{{"repositoryId", repoType, false}},
		check: func(in map[string]any) (op.Op, error) {
			if h, ok := in["headRepositoryId"]; ok && h != in["repositoryId"] {
				return "", errorf("agents may only open PRs from a branch in the same repo")
			}
			// "owner:branch" names a branch in someone else's fork.
			if h, _ := in["headRefName"].(string); strings.Contains(h, ":") {
				return "", errorf("agents may only open PRs from a branch in the same repo")
			}
			return "", nil
		},
	},
	"updatePullRequest":              {op: op.PREdit, fields: []string{"pullRequestId", "title", "body", "state", "baseRefName", "maintainerCanModify"}, opFields: assignLabel, binds: []bind{{"pullRequestId", pr, true}}},
	"closePullRequest":               {op: op.PREdit, fields: []string{"pullRequestId"}, binds: []bind{{"pullRequestId", pr, true}}},
	"reopenPullRequest":              {op: op.PREdit, fields: []string{"pullRequestId"}, binds: []bind{{"pullRequestId", pr, true}}},
	"markPullRequestReadyForReview":  {op: op.PREdit, fields: []string{"pullRequestId"}, binds: []bind{{"pullRequestId", pr, true}}},
	"convertPullRequestToDraft":      {op: op.PREdit, fields: []string{"pullRequestId"}, binds: []bind{{"pullRequestId", pr, true}}},
	"requestReviews":                 {op: op.PRReviewers, fields: []string{"pullRequestId", "userIds", "union"}, binds: []bind{{"pullRequestId", pr, true}}},
	"requestReviewsByLogin":          {op: op.PRReviewers, fields: []string{"pullRequestId", "userLogins", "union"}, binds: []bind{{"pullRequestId", pr, true}}},
	"addPullRequestReview":           {op: op.ReviewComment, fields: []string{"pullRequestId", "body", "event", "commitOID", "threads"}, binds: []bind{{"pullRequestId", pr, false}}, check: reviewVerdict},
	"submitPullRequestReview":        {op: op.ReviewComment, fields: []string{"pullRequestId", "pullRequestReviewId", "body", "event"}, binds: []bind{{"pullRequestId", pr, false}, {"pullRequestReviewId", []string{"PullRequestReview"}, true}}, check: reviewVerdict},
	"addPullRequestReviewThread":     {op: op.ReviewComment, fields: []string{"pullRequestId", "pullRequestReviewId", "body", "path", "line", "side", "startLine", "startSide", "subjectType"}, binds: []bind{{"pullRequestId", pr, false}, {"pullRequestReviewId", []string{"PullRequestReview"}, true}}},
	"addComment":                     {op: op.Comment, fields: []string{"subjectId", "body"}, binds: []bind{{"subjectId", issueOr, false}}},
	"updateIssueComment":             {op: op.Comment, fields: []string{"id", "body"}, binds: []bind{{"id", []string{"IssueComment"}, true}}},
	"createIssue":                    {op: op.IssueCreate, fields: []string{"repositoryId", "title", "body"}, opFields: assignLabel, binds: []bind{{"repositoryId", repoType, false}}},
	"updateIssue":                    {op: op.IssueEdit, fields: []string{"id", "title", "body", "state"}, opFields: assignLabel, binds: []bind{{"id", issue, true}}},
	"closeIssue":                     {op: op.IssueEdit, fields: []string{"issueId", "stateReason"}, binds: []bind{{"issueId", issue, true}}},
	"reopenIssue":                    {op: op.IssueEdit, fields: []string{"issueId"}, binds: []bind{{"issueId", issue, true}}},
	"replaceActorsForAssignable":     {op: op.Assign, fields: []string{"assignableId", "actorIds", "actorLogins"}, binds: []bind{{"assignableId", issueOr, true}}},
	"addAssigneesToAssignable":       {op: op.Assign, fields: []string{"assignableId", "assigneeIds"}, binds: []bind{{"assignableId", issueOr, true}}},
	"removeAssigneesFromAssignable":  {op: op.Assign, fields: []string{"assignableId", "assigneeIds"}, binds: []bind{{"assignableId", issueOr, true}}},
	"resolveReviewThread":            {op: op.ReviewComment, fields: []string{"threadId"}, binds: []bind{{"threadId", []string{"PullRequestReviewThread"}, false}}},
	"unresolveReviewThread":          {op: op.ReviewComment, fields: []string{"threadId"}, binds: []bind{{"threadId", []string{"PullRequestReviewThread"}, false}}},
	"updatePullRequestReviewComment": {op: op.ReviewComment, fields: []string{"pullRequestReviewCommentId", "body"}, binds: []bind{{"pullRequestReviewCommentId", []string{"PullRequestReviewComment"}, true}}},

	"mergePullRequest":            {op: op.PRMerge, fields: []string{"pullRequestId", "commitHeadline", "commitBody", "expectedHeadOid", "mergeMethod", "authorEmail"}, binds: []bind{{"pullRequestId", pr, false}}},
	"enqueuePullRequest":          {op: op.PRMerge, fields: []string{"pullRequestId", "expectedHeadOid"}, binds: []bind{{"pullRequestId", pr, false}}},
	"dequeuePullRequest":          {op: op.PRMerge, fields: []string{"id"}, binds: []bind{{"id", pr, false}}},
	"enablePullRequestAutoMerge":  {op: op.PRMerge, fields: []string{"pullRequestId", "commitHeadline", "commitBody", "expectedHeadOid", "mergeMethod", "authorEmail"}, binds: []bind{{"pullRequestId", pr, false}}},
	"disablePullRequestAutoMerge": {op: op.PRMerge, fields: []string{"pullRequestId"}, binds: []bind{{"pullRequestId", pr, false}}},
	"addLabelsToLabelable":        {op: op.Labels, fields: []string{"labelableId", "labelIds"}, binds: []bind{{"labelableId", issueOr, false}}},
	"removeLabelsFromLabelable":   {op: op.Labels, fields: []string{"labelableId", "labelIds"}, binds: []bind{{"labelableId", issueOr, false}}},
}

// CheckNode decides a resolved node against its use.
func CheckNode(use NodeUse, n Node, allowed func(github.Repo) (write bool, ops op.Set, ok bool)) error {
	if !slices.Contains(use.Types, n.Type) {
		return errorf("%s names a %s, which hallpass doesn't allow there", use.Where, n.Type)
	}
	write, ops, ok := allowed(n.Repo)
	switch {
	case !ok:
		return errorf("%s is in %s, which isn't in hallpass's allowlist", use.Where, n.Repo)
	case use.Write && !write:
		return errorf("agents may only read %s", n.Repo)
	case use.Authored && !n.Authored:
		return errorf("agents may only change PRs, issues, and comments you wrote")
	}
	// A write that names no operation would pass CheckOps, so refuse it.
	if use.Write && len(use.Ops) == 0 {
		return errorf("hallpass has no operation for %s, so it refuses it", use.Where)
	}
	return CheckOps(use.Ops, ops, n.Repo)
}

// CheckOps refuses the first operation in need that have lacks, with the
// command that would allow it.
func CheckOps(need []op.Op, have op.Set, repo github.Repo) error {
	for _, o := range need {
		info, known := op.Lookup(string(o))
		if !known {
			return errorf("hallpass has no operation named %q, so it refuses this request", o)
		}
		if !have.Has(o) {
			return errorf("agents may not %s in %s. To allow it: sudo /opt/hallpass/bin/hallpass policy allow %s --repo %s", info.Does, repo, o, repo)
		}
	}
	return nil
}

// normalizeNumbers turns json.Number into int64 or float64, which the
// variable coercion understands.
func normalizeNumbers(v map[string]any) map[string]any {
	var conv func(any) any
	conv = func(x any) any {
		switch t := x.(type) {
		case json.Number:
			if i, err := t.Int64(); err == nil {
				return i
			}
			f, _ := t.Float64()
			return f
		case map[string]any:
			for k, e := range t {
				t[k] = conv(e)
			}
		case []any:
			for i, e := range t {
				t[i] = conv(e)
			}
		}
		return x
	}
	if v == nil {
		return map[string]any{}
	}
	conv(v)
	return v
}

// strictObject checks that body is one JSON object with only the given
// keys, each at most once, and nothing after it.
func strictObject(body []byte, keys []string) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return errorf("request body must be one JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return errorf("malformed JSON")
		}
		ks, _ := k.(string)
		if !slices.Contains(keys, ks) {
			return errorf("hallpass doesn't accept %q in this request", ks)
		}
		if seen[ks] {
			return errorf("request repeats %q", ks)
		}
		seen[ks] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return errorf("malformed JSON")
		}
	}
	if _, err := dec.Token(); err != nil {
		return errorf("malformed JSON")
	}
	if dec.More() {
		return errorf("request has data after its JSON object")
	}
	if _, err := dec.Token(); err == nil {
		return errorf("request has data after its JSON object")
	}
	return nil
}
