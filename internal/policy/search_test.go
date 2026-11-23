package policy

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
)

// An ISSUE_ADVANCED search reaches GitHub as a plain ISSUE search, which is
// the one SearchRepo confines, without gh's parentheses.
func TestAdvancedSearchIsSentAsIssue(t *testing.T) {
	t.Parallel()
	const byVar = `query($q:String!,$type:SearchType!){search(query:$q,type:$type,first:5){issueCount}}`
	vars := func(q string) map[string]any { return map[string]any{"q": q, "type": "ISSUE_ADVANCED"} }

	for q, want := range map[string]string{
		"( is:merged ) repo:acme/widgets type:pr":      "is:merged repo:acme/widgets type:pr",
		"( status is:open ) repo:acme/widgets type:pr": "status is:open repo:acme/widgets type:pr",
		"is:merged repo:acme/widgets":                  "is:merged repo:acme/widgets",
	} {
		g, err := ClassifyGraphQL(gql(byVar, vars(q)), nil)
		if err != nil {
			t.Errorf("%q: %v", q, err)
			continue
		}
		var sent struct {
			Variables struct{ Q, Type string } `json:"variables"`
		}
		if err := json.Unmarshal(g.Body, &sent); err != nil {
			t.Fatal(err)
		}
		if sent.Variables.Q != want || sent.Variables.Type != "ISSUE" {
			t.Errorf("%q: sent %q as %s, want %q as ISSUE", q, sent.Variables.Q, sent.Variables.Type, want)
		}
		if len(g.Repos) != 1 || g.Repos[0].String() != "acme/widgets" {
			t.Errorf("%q: repos %v", q, g.Repos)
		}
	}

	g, err := ClassifyGraphQL(gql(`{search(query:"( is:merged ) repo:acme/widgets",type:ISSUE_ADVANCED,first:5){issueCount}}`, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(g.Body); strings.Contains(s, "ISSUE_ADVANCED") || strings.Contains(s, "( is:merged") {
		t.Errorf("literal search sent unchanged: %s", s)
	}

	for _, q := range []string{
		"( a ) repo:acme/widgets ( b )",
		"(a) repo:acme/widgets",
		"( a ( b ) ) repo:acme/widgets",
		"( label: ) repo:acme/widgets",
		"label: repo:acme/widgets",
		"( a OR b ) repo:acme/widgets",
		`( "a b" ) repo:acme/widgets`,
		"( a ) repo:acme/widgets repo:acme/secret",
		"( a ) org:acme",
		"( a )",
	} {
		if _, err := ClassifyGraphQL(gql(byVar, vars(q)), nil); err == nil {
			t.Errorf("%q passed", q)
		}
	}

	for _, typ := range []string{"ISSUE_SEMANTIC", "ISSUE_HYBRID", "REPOSITORY"} {
		if _, err := ClassifyGraphQL(gql(byVar, map[string]any{"q": "repo:acme/widgets", "type": typ}), nil); err == nil {
			t.Errorf("search of type %s passed", typ)
		}
	}

	// A root field before the search was checked with the variable's old
	// value, so the rewrite can't run.
	shared := `query($q:String!,$type:SearchType!){a:search(query:$q,type:ISSUE,first:1){issueCount} b:search(query:$q,type:$type,first:1){issueCount}}`
	if _, err := ClassifyGraphQL(gql(shared, vars("( a ) repo:acme/widgets")), nil); err == nil {
		t.Error("advanced search after another root field passed")
	}
}

func TestSearchRepo(t *testing.T) {
	t.Parallel()
	allowed := []string{
		// What gh 2.98.0 sends for gh search issues --repo.
		`( foo ) repo:acme/widgets type:issue`,
		`repo:acme/widgets`,
		`is:pr -label:x repo:acme/widgets`,
		`repo:acme/widgets superuser: café`,
	}
	for _, q := range allowed {
		repo, err := SearchRepo(q)
		if err != nil || repo.String() != "acme/widgets" {
			t.Errorf("%q: %v, %v", q, repo, err)
		}
	}
	refused := []struct{ q, want string }{
		// GitHub reads each of these as a search of every repo the token
		// can see: repo: becomes part of the -label: term before it, or,
		// in capitals, plain text.
		{"is:issue secret -label:x\trepo:acme/widgets", "only plain spaces"},
		{"secret -label:x\nrepo:acme/widgets", "only plain spaces"},
		{"secret -label:x\vrepo:acme/widgets", "only plain spaces"},
		{"secret -label:x\u00a0repo:acme/widgets", "only plain spaces"},
		{"secret -label:x\u2028repo:acme/widgets", "only plain spaces"},
		{"secret -label:x\u3000repo:acme/widgets", "only plain spaces"},
		{"secret -label:x\u200brepo:acme/widgets", "only plain spaces"},
		{"secret -label:x(repo:acme/widgets)", "after a space"},
		{"secret (repo:acme/widgets)", "after a space"},
		{"secret REPO:acme/widgets", "in lowercase"},
		{"secret Repo:acme/widgets", "in lowercase"},
		{"secret -repo:acme/widgets", "after a space"},
		{"secret x.repo:acme/widgets", "after a space"},

		{"secret", "add repo:OWNER/NAME"},
		{"repo:acme/widgets repo:acme/secret", "one repo:"},
		{"repo:acme/widgets x,repo:acme/secret", "one repo:"},
		{"repo:acme/widgets org:acme", "doesn't allow org:"},
		{"repo:acme/widgets -user:acme", "doesn't allow -user:"},
		{"repo:acme/widgets (OWNER:acme)", "doesn't allow (OWNER:"},
		{"repo:acme/widgets bug OR feature", "boolean operators"},
		{"repo:acme/widgets (not) bug", "boolean operators"},
		{`label:"x repo:acme/widgets y"`, "quotes"},
		{`repo:acme/widgets it's`, "quotes"},
		{"repo:acme/widgets \xff", "valid UTF-8"},
		{"repo:acme", "not a GitHub repo path"},
		{"repo:acme/widgets,acme/secret", "not a GitHub repo path"},
		{"repo:acme/widgets)", "not a GitHub repo path"},
		{"repo:repo:acme/widgets", "not a GitHub repo path"},
		{"repo:/acme/widgets/", "repo:OWNER/NAME exactly"},
		{"repo:acme/widgets.git", "repo:OWNER/NAME exactly"},
	}
	for _, c := range refused {
		if repo, err := SearchRepo(c.q); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, %v, want %q", c.q, repo, err, c.want)
		}
	}
}

// A search the broker can't confine goes without the token, over REST and
// not at all over GraphQL.
func TestSearchBypassesGetNoToken(t *testing.T) {
	t.Parallel()
	for _, q := range []string{
		"is:issue secret -label:x\trepo:acme/widgets",
		"secret -label:x(repo:acme/widgets)",
		"secret REPO:acme/widgets",
	} {
		r, err := ClassifyREST("GET", "/search/issues?"+url.Values{"q": {q}}.Encode(), nil, nil)
		if err != nil || !r.Anonymous || r.Repo != nil {
			t.Errorf("REST %q: %+v, %v, want a read without the token", q, r, err)
		}
		body := gql(`query($q:String!){search(query:$q,type:ISSUE,first:5){nodes{... on Issue{body}}}}`, map[string]any{"q": q})
		if g, err := ClassifyGraphQL(body, nil); err == nil {
			t.Errorf("GraphQL %q: allowed for %v", q, g.Repos)
		}
	}
}

func TestIssueAnswer(t *testing.T) {
	t.Parallel()
	check := issueAnswer(github.Repo{Owner: "acme", Name: "widgets"})
	cases := []struct {
		answer string
		ok     bool
	}{
		{`{"total_count":0,"items":[]}`, true},
		{`{"items":[{"repository_url":"https://api.github.com/repos/acme/widgets"},{"repository_url":"https://api.github.com/repos/Acme/Widgets"}]}`, true},
		{`{"items":[{"repository_url":"https://api.github.com/repos/acme/widgets"},{"repository_url":"https://api.github.com/repos/acme/secret"}]}`, false},
		{`{"items":[{"repository_url":"https://api.github.com/repos/acme/widgets/x"}]}`, false},
		{`{"items":[{"number":1}]}`, false},
		{`{"items":[1]}`, false},
		{`{"total_count":3}`, false},
		{`[]`, false},
	}
	for _, c := range cases {
		var v any
		if err := json.Unmarshal([]byte(c.answer), &v); err != nil {
			t.Fatal(err)
		}
		if err := check(v); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.answer, err, c.ok)
		}
	}
}
