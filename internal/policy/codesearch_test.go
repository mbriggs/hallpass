package policy

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
)

func TestCodeSearchRepo(t *testing.T) {
	t.Parallel()
	// The first four are what gh 2.98.0 sent for gh search code --repo.
	allowed := []string{
		`widget repo:acme/widgets`,
		`"\"exact phrase\" widget" extension:go filename:main.go in:file language:go repo:acme/widgets`,
		`widget in:path repo:acme/widgets`,
		`"exact phrase" repo:acme/widgets`,
		`REPO:Acme/Widgets size:>100 path:src fork:true`,
		`"a or b" "not this" repo:acme/widgets`,
		`(widget) repo:acme/widgets`,
		`repo:acme/widgets (widget)`,
		`superuser: repo:acme/widgets`,
		`'single' repo:acme/widgets`,
	}
	for _, q := range allowed {
		repo, err := CodeSearchRepo(q)
		if err != nil || repo.Key() != "acme/widgets" {
			t.Errorf("%s: %v, %v", q, repo, err)
		}
	}
	refused := []struct{ q, want string }{
		{`widget`, "add repo:OWNER/NAME (gh search code --repo OWNER/NAME)"},
		{`widget user:acme`, "doesn't allow user:"},
		{`widget org:acme repo:acme/widgets`, "doesn't allow org:"},
		{`widget owner:acme repo:acme/widgets`, "doesn't allow owner:"},
		{`widget -user:acme repo:acme/widgets`, "doesn't allow user:"},
		{`"user:acme" repo:acme/widgets`, "doesn't allow user:"},
		{`repo:acme/widgets repo:acme/secret`, "one repo:"},
		{`"repo:acme/secret" repo:acme/widgets`, "one repo:"},
		{`x.repo:acme/secret repo:acme/widgets`, "one repo:"},
		{"x repo:acme/secret repo:acme/widgets", "one repo:"},
		{`"repo:acme/widgets"`, "outside quotes"},
		{`-repo:acme/widgets`, "outside quotes"},
		{`repo:acme/widgets"x"`, "outside quotes"},
		{`foo OR bar repo:acme/widgets`, "boolean operators"},
		{`NOT bar repo:acme/widgets`, "boolean operators"},
		{`"unclosed repo:acme/widgets`, "unclosed quote"},
		{`"\" repo:acme/widgets`, "unclosed quote"},
		{`widget repo:acme`, "not a GitHub repo path"},
		{`x(repo:acme/widgets`, "space before repo:"},
		{"x\trepo:acme/widgets", "space before repo:"},
		{`repo:/acme/widgets/`, "repo:OWNER/NAME exactly"},
		{`repo:acme/widgets.git`, "repo:OWNER/NAME exactly"},
	}
	for _, c := range refused {
		if repo, err := CodeSearchRepo(c.q); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, %v, want %q", c.q, repo, err, c.want)
		}
	}
}

func TestClassifyCodeSearch(t *testing.T) {
	t.Parallel()
	target := "/search/code?page=1&per_page=30&q=widget+repo%3Aacme%2Fwidgets"
	r, err := ClassifyREST("GET", target, nil, nil)
	if err != nil || r.Route != "GET /search/code" || r.Repo.String() != "acme/widgets" || !r.NeedsToken || r.Answer == nil || r.Anonymous || r.Path != target {
		t.Fatalf("%+v, %v", r, err)
	}
	// Unlike other GETs nothing covers, a code search the broker can't
	// confine isn't sent without the token: GitHub would only answer 401.
	for _, q := range []string{"widget", "widget user:acme"} {
		r, err := ClassifyREST("GET", "/search/code?q="+url.QueryEscape(q), nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--repo OWNER/NAME") {
			t.Errorf("%s: %+v, %v", q, r, err)
		}
	}
}

func TestCodeAnswer(t *testing.T) {
	t.Parallel()
	repo := github.Repo{Owner: "acme", Name: "widgets"}
	item := func(full string) string {
		return `{"name":"x","path":"a.go","repository":{"full_name":"` + full + `"},"text_matches":[{"fragment":"code"}]}`
	}
	const other = "with a result from another repo"
	cases := []struct {
		body, want string
	}{
		{`{"total_count":2,"items":[` + item("acme/widgets") + `,` + item("ACME/Widgets") + `]}`, ""},
		{`{"total_count":0,"items":[]}`, ""},
		{`{"total_count":2,"items":[` + item("acme/widgets") + `,` + item("acme/secret") + `]}`, other},
		{`{"items":[` + item("acme/widgets-old") + `]}`, "If acme/widgets was renamed"},
		{`{"items":[{"path":"a.go"}]}`, other},
		{`{"items":[{"path":"a.go","repository":{"full_name":7}}]}`, other},
		{`{"items":{}}`, "no list of results"},
		{`{"items":null}`, "no list of results"},
		{`[]`, "no list of results"},
		{`{"items":["acme/widgets"]}`, other},
	}
	for _, c := range cases {
		var v any
		if err := json.Unmarshal([]byte(c.body), &v); err != nil {
			t.Fatal(err)
		}
		err := codeAnswer(repo)(v)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.body, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", c.body, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "acme/secret") {
			t.Errorf("%s: the refusal names the other repo: %v", c.body, err)
		}
	}
}

// A contents deny would turn code search into a test of what the denied
// files hold, so it closes code search in that repo entirely.
func TestCodeSearchContentsDeny(t *testing.T) {
	t.Parallel()
	target := "/search/code?q=" + url.QueryEscape("AKIA repo:acme/widgets")
	for _, c := range []struct {
		deny []string
		want string
	}{
		{nil, ""},
		{[]string{"deployments", "actions/runs/#/logs"}, ""},
		{[]string{"contents/secret/**"}, "the policy for acme/widgets denies reading some of its files"},
		{[]string{"contents"}, "the policy for acme/widgets denies reading some of its files"},
	} {
		g := &Grants{Reads: func(github.Repo) []ReadLayer {
			return []ReadLayer{{From: "global"}, {From: "acme/widgets", Deny: c.deny}}
		}}
		r, err := ClassifyREST("GET", target, nil, g)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("deny %v: %v", c.deny, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("deny %v: %+v, %v", c.deny, r, err)
		}
	}
}

// A code search the broker allows names exactly one scope, repo:R for the
// repo it returns, however GitHub splits the query into terms. This checks
// that against the raw text, with no tokenizing at all.
func FuzzCodeSearchRepo(f *testing.F) {
	for _, q := range []string{
		`widget repo:acme/widgets`,
		`"\"exact phrase\" widget" extension:go filename:main.go in:file language:go repo:acme/widgets`,
		`widget in:path repo:acme/widgets`,
		`"repo:acme/secret" repo:acme/widgets`,
		`foo "bar \\" repo:acme/x" repo:acme/widgets`,
		`(a) -org:acme repo:acme/widgets`,
		"x\trepo:acme/widgets\n",
	} {
		f.Add(q)
	}
	scope := regexp.MustCompile(`(?:^|[^a-z0-9])(repo|org|user|owner):([^\s()"]*)`)
	f.Fuzz(func(t *testing.T, q string) {
		repo, err := CodeSearchRepo(q)
		if err != nil {
			return
		}
		ms := scope.FindAllStringSubmatch(strings.ToLower(q), -1)
		if len(ms) != 1 || ms[0][1] != "repo" {
			t.Fatalf("%q allowed for %s, but holds scopes %q", q, repo, ms)
		}
		if got, err := github.ParseRepo(ms[0][2]); err != nil || got.Key() != repo.Key() {
			t.Fatalf("%q allowed for %s, but its repo: names %q", q, repo, ms[0][2])
		}
	})
}
