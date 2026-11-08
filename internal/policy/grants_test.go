package policy

import (
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
)

func TestCheckRead(t *testing.T) {
	for _, ok := range []string{"deployments", "deployments/#/statuses", "pages", "environments", "deployments/**", "traffic/views",
		// Refused by default, and config may open them.
		"actions/variables", "actions/variables/*", "rulesets", "rulesets/#", "rules/branches/*",
		// A branch, without its protection.
		"branches/*",
	} {
		if err := CheckRead(ok); err != nil {
			t.Errorf("CheckRead(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{
		"*", "#", "**", "a/**/b", "Deployments", "",
		// The floor, directly and through wildcards.
		"secrets", "actions/secrets", "actions/secrets/*", "actions/*", "actions/**",
		"environments/*/secrets", "environments/**", "environments/*/*", "hooks/#",
		"branches/*/protection", "branches/**", "branches/*/*", "branches/main/protection/required_status_checks",
	} {
		if err := CheckRead(bad); err == nil {
			t.Errorf("CheckRead(%q) passed", bad)
		}
	}
}

// No built-in read reaches the floor, so the floor only ever narrows what
// config adds. The exception is branches/**, which must cover branch names
// with slashes; the floor takes protection out of it on every request.
func TestBuiltinReadsClearTheFloor(t *testing.T) {
	for _, r := range reads {
		if r != "" && r != "branches/**" && overlapsFloor(r) {
			t.Errorf("built-in read %q overlaps the read floor", r)
		}
	}
}

func TestBranchProtectionIsFloored(t *testing.T) {
	for path, ok := range map[string]bool{
		"branches/main":                           true,
		"branches/agent/matrix":                   true,
		"branches/main/protection":                false,
		"branches/agent/x/protection":             false,
		"branches/main/protection/enforce_admins": false,
		"actions/variables":                       false, // refused by default
		"rulesets":                                false, // refused by default
	} {
		_, err := ClassifyREST("GET", "/repos/acme/widgets/"+path, nil, nil)
		if ok != (err == nil) {
			t.Errorf("GET %s: err = %v", path, err)
		}
	}
	// Variables and rulesets open with a grant; protection doesn't.
	g := grants(nil, ReadLayer{From: "global", Allow: []string{"actions/variables", "rulesets", "branches/**"}})
	for path, ok := range map[string]bool{"actions/variables": true, "rulesets": true, "branches/main/protection": false} {
		_, err := ClassifyREST("GET", "/repos/acme/widgets/"+path, nil, g)
		if ok != (err == nil) {
			t.Errorf("granted GET %s: err = %v", path, err)
		}
	}
}

func TestCheckField(t *testing.T) {
	for _, ok := range []string{"Repository.hasProjectsEnabled", "Repository.visibility", "RepositoryOwner.login"} {
		if err := CheckField(ok); err != nil {
			t.Errorf("CheckField(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{
		"Repository.tempCloneToken", // never readable
		"Repository.issues",         // a hop to other objects
		"Repository.defaultBranchRef",
		"Repository.nope", "Nope.id", "Repository", "",
	} {
		if err := CheckField(bad); err == nil {
			t.Errorf("CheckField(%q) passed", bad)
		}
	}
}

// grants builds Grants with one layer per entry, in order.
func grants(fields map[string]bool, layers ...ReadLayer) *Grants {
	return &Grants{Fields: fields, Reads: func(github.Repo) []ReadLayer { return layers }}
}

func TestRESTReadGrants(t *testing.T) {
	cases := []struct {
		name, path string
		g          *Grants
		ok         bool
		msg        string // in the refusal
	}{
		{"not built in", "/repos/acme/widgets/deployments", nil, false, "policy allow read:deployments --repo acme/widgets"},
		{"numbers become #", "/repos/acme/widgets/deployments/12/statuses", nil, false, "policy allow read:deployments/#/statuses --repo acme/widgets"},
		{"allowed", "/repos/acme/widgets/deployments", grants(nil, ReadLayer{From: "global", Allow: []string{"deployments"}}), true, ""},
		{"deny a built-in", "/repos/acme/widgets/actions/runs/5/logs", grants(nil, ReadLayer{From: "acme/widgets", Deny: []string{"actions/runs/#/logs"}}), false, "The policy for acme/widgets denies it"},
		{"exact entry beats global", "/repos/acme/widgets/deployments", grants(nil,
			ReadLayer{From: "global", Allow: []string{"deployments"}},
			ReadLayer{From: "acme/widgets", Deny: []string{"deployments"}}), false, "acme/widgets denies"},
		{"deny wins in a layer", "/repos/acme/widgets/deployments", grants(nil, ReadLayer{From: "global", Allow: []string{"deployments"}, Deny: []string{"deployments"}}), false, ""},
		{"later allow beats earlier deny", "/repos/acme/widgets/pulls", grants(nil,
			ReadLayer{From: "acme/*", Deny: []string{"pulls"}},
			ReadLayer{From: "acme/widgets", Allow: []string{"pulls"}}), true, ""},
		// Grants built by hand, past CheckRead, still can't open the floor.
		{"floor", "/repos/acme/widgets/actions/secrets", grants(nil, ReadLayer{From: "global", Allow: []string{"actions/**"}}), false, "never allows"},
		{"floor names no command", "/repos/acme/widgets/environments/prod/secrets", nil, false, "never allows"},
	}
	for _, c := range cases {
		r, err := ClassifyREST("GET", c.path, nil, c.g)
		if c.ok != (err == nil) {
			t.Errorf("%s: err = %v", c.name, err)
			continue
		}
		if err != nil && !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: %q lacks %q", c.name, err, c.msg)
		}
		if err != nil && strings.Contains(c.msg, "never") && strings.Contains(err.Error(), "To allow it") {
			t.Errorf("%s: a floor refusal offers a command: %v", c.name, err)
		}
		if err == nil && r.Follow {
			t.Errorf("%s: a configured route follows redirects", c.name)
		}
	}
}

func TestGraphQLFieldGrants(t *testing.T) {
	parent := gql(`{repository(owner:"acme",name:"widgets"){parent{hasProjectsEnabled}}}`, nil)
	_, err := ClassifyGraphQL(parent, nil)
	if err == nil || !strings.Contains(err.Error(), "policy allow field:Repository.hasProjectsEnabled") {
		t.Fatalf("built-ins: %v", err)
	}
	if _, err := ClassifyGraphQL(parent, grants(map[string]bool{"Repository.hasProjectsEnabled": true})); err != nil {
		t.Errorf("allowed: %v", err)
	}

	desc := gql(`{repository(owner:"acme",name:"widgets"){description parent{description}}}`, nil)
	if _, err := ClassifyGraphQL(desc, nil); err != nil {
		t.Fatalf("built-in description: %v", err)
	}
	g := grants(map[string]bool{"Repository.description": false})
	if _, err := ClassifyGraphQL(desc, g); err == nil {
		t.Errorf("denied description still passes through parent")
	}
	// The deny covers only reads outside the named repo.
	if _, err := ClassifyGraphQL(gql(`{repository(owner:"acme",name:"widgets"){description}}`, nil), g); err != nil {
		t.Errorf("deny reached the named repo: %v", err)
	}

	// A grant on an object field, built past CheckField, opens no hop.
	hop := gql(`{repository(owner:"acme",name:"widgets"){parent{issues(first:1){nodes{body}}}}}`, nil)
	if _, err := ClassifyGraphQL(hop, grants(map[string]bool{"Repository.issues": true, "Issue.body": true})); err == nil {
		t.Errorf("a field grant opened a hop to another repo's issues")
	}
	// Nor does a refusal of a hop offer a command.
	if _, err := ClassifyGraphQL(hop, nil); err == nil || strings.Contains(err.Error(), "To allow it") {
		t.Errorf("hop refusal: %v", err)
	}
}
