package policy

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
)

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
