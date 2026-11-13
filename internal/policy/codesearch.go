package policy

import (
	"regexp"
	"strings"

	"github.com/mbriggs/hallpass/internal/github"
)

// scopes finds the qualifiers that pick which repos a search covers,
// wherever they appear, quoted or not, and with any non-alphanumeric
// character before them, so a query GitHub splits differently from the
// broker still holds no scope but the one repo: the broker checked.
var scopes = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(repo|org|user|owner):`)

// CodeSearchRepo reads the one repo a REST code search (GET /search/code)
// is confined to. The query must name it with exactly one repo:OWNER/NAME,
// as its own term outside quotes, and no org:, user:, or owner: anywhere.
// Unlike SearchRepo, it allows quoted phrases, balanced and with gh's \"
// escapes, since the broker also checks every result GitHub returns.
func CodeSearchRepo(q string) (github.Repo, error) {
	const add = "add repo:OWNER/NAME (gh search code --repo OWNER/NAME)"
	n, at := 0, ""
	for _, m := range scopes.FindAllStringSubmatch(q, -1) {
		if strings.ToLower(m[1]) != "repo" {
			return github.Repo{}, errorf("hallpass searches code only within one repo, so it doesn't allow %s: anywhere in the query, even in quotes; %s", strings.ToLower(m[1]), add)
		}
		n, at = n+1, m[0]
	}
	switch {
	case n == 0:
		return github.Repo{}, errorf("hallpass searches code only within one repo; %s", add)
	case n > 1:
		return github.Repo{}, errorf("hallpass allows one repo: per code search, and doesn't allow repo: anywhere else in the query, even in quotes")
	}
	terms, err := searchTerms(q)
	if err != nil {
		return github.Repo{}, err
	}
	for _, t := range terms {
		if t.quoted {
			continue
		}
		switch low := strings.ToLower(t.text); {
		case low == "or" || low == "and" || low == "not":
			return github.Repo{}, errorf("hallpass doesn't allow boolean operators in searches; quote %s to search for the word", t.text)
		case strings.HasPrefix(low, "repo:"):
			// gh writes repo: after a space. Anything else before it is a
			// place GitHub might split the query differently.
			if at[0] != ' ' && len(at) != len("repo:") {
				return github.Repo{}, errorf("hallpass needs a space before repo: in a code search")
			}
			// GitHub gets the text as written, so it must be the repo
			// exactly, without the slashes or suffix ParseRepo would trim.
			name := t.text[len("repo:"):]
			repo, err := github.ParseRepo(name)
			if err == nil && repo.String() != name {
				err = errorf("hallpass needs repo:OWNER/NAME exactly, not repo:%s", name)
			}
			return repo, err
		}
	}
	return github.Repo{}, errorf("hallpass reads repo:OWNER/NAME only as a term of its own, outside quotes; %s", add)
}

type searchTerm struct {
	text   string
	quoted bool
}

// searchTerms splits a search query into terms at spaces and parentheses
// outside double quotes. Inside quotes, \" and \\ stand for " and \, as gh
// writes a phrase that holds quotes. A term with any quoted part is quoted.
func searchTerms(q string) ([]searchTerm, error) {
	var out []searchTerm
	var b strings.Builder
	in, quoted := false, false
	flush := func() {
		if b.Len() > 0 || quoted {
			out = append(out, searchTerm{b.String(), quoted})
		}
		b.Reset()
		quoted = false
	}
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case in && c == '\\' && i+1 < len(q) && (q[i+1] == '"' || q[i+1] == '\\'):
			i++
			b.WriteByte(q[i])
		case c == '"':
			in, quoted = !in, true
		case !in && strings.IndexByte(" \t\r\n()", c) >= 0:
			flush()
		default:
			b.WriteByte(c)
		}
	}
	if in {
		return nil, errorf("hallpass doesn't allow a search with an unclosed quote")
	}
	flush()
	return out, nil
}

// codeAnswer checks GitHub's answer to a code search confined to repo:
// every result must be a file in repo, whatever GitHub made of the query.
// The broker refuses the whole answer otherwise. The refusal doesn't name
// the other repo, which may be a private one the allowlist doesn't cover.
func codeAnswer(repo github.Repo) func(any) error {
	return func(v any) error {
		m, _ := v.(map[string]any)
		items, ok := m["items"].([]any)
		if !ok {
			return errorf("GitHub's answer to a code search had no list of results")
		}
		for _, it := range items {
			item, _ := it.(map[string]any)
			r, _ := item["repository"].(map[string]any)
			if name, _ := r["full_name"].(string); !strings.EqualFold(name, repo.String()) {
				return errorf("GitHub answered a code search in %s with a result from another repo, so hallpass refused the whole answer. If %s was renamed, search under its new name", repo, repo)
			}
		}
		return nil
	}
}

// issueAnswer checks GitHub's answer to an issue or PR search confined to
// repo, as codeAnswer does for code: every result must be in repo, however
// GitHub read the query.
func issueAnswer(repo github.Repo) func(any) error {
	return func(v any) error {
		m, _ := v.(map[string]any)
		items, ok := m["items"].([]any)
		if !ok {
			return errorf("GitHub's answer to a search had no list of results")
		}
		for _, it := range items {
			item, _ := it.(map[string]any)
			url, _ := item["repository_url"].(string)
			if _, name, ok := strings.CutLast(url, "/repos/"); !ok || !strings.EqualFold(name, repo.String()) {
				return errorf("GitHub answered a search in %s with a result from another repo, so hallpass refused the whole answer. If %s was renamed, search under its new name", repo, repo)
			}
		}
		return nil
	}
}

// deniesContents names the config layer that denies a contents read in
// repo, or "". Code search would reach those files, and whether a search
// is refused or comes back empty would tell what they hold, so a repo with
// such a deny can't be searched at all.
func (g *Grants) deniesContents(repo github.Repo) string {
	if g == nil || g.Reads == nil {
		return ""
	}
	for _, l := range g.Reads(repo) {
		for _, p := range l.Deny {
			if p == "contents" || strings.HasPrefix(p, "contents/") {
				return l.From
			}
		}
	}
	return ""
}
