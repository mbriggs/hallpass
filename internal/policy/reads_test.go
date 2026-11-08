package policy

import (
	"strings"
	"testing"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

// Reads that match a REST pattern but could reach past the repo are refused,
// each for its own reason.
func TestRESTReadsStayInRepo(t *testing.T) {
	refused := map[string]string{
		"/repos/acme/widgets/issues/1/timeline":                 "doesn't allow reading",
		"/repos/acme/widgets/compare/main...other:main":         "not with a fork",
		"/repos/acme/widgets/compare/main...other:widgets:main": "not with a fork",
		"/repos/acme/widgets/compare/main..abc1234":             "full SHA",
		"/repos/acme/widgets/commits/abc1234":                   "full SHA",
		"/repos/acme/widgets/commits/abc1234/status":            "full SHA",
		"/repos/acme/widgets/git/trees/abc1234":                 "full SHA",
		"/repos/acme/widgets/git/commits/abcdef12":              "full SHA",
		"/repos/acme/widgets/git/blobs/abcd":                    "full SHA",
		"/repos/acme/widgets/contents/README.md?ref=abc1234":    "full SHA",
		"/repos/acme/widgets/commits?sha=abc1234":               "full SHA",
		"/repos/acme/widgets/commits/abc1234~0":                 "full SHA",
		"/repos/acme/widgets/git/trees/abc1234^0":               "full SHA",
		"/repos/acme/widgets/compare/main...abc1234~0":          "full SHA",
		"/repos/acme/widgets/contents/README.md?ref=abc1234~0":  "full SHA",
		"/repos/acme/widgets/commits?sha=main@{1}":              "full SHA",
		// The read floor refuses branch protection before any other check.
		"/repos/acme/widgets/branches/main/protection":                               "never allows reading",
		"/repos/acme/widgets/branches/feature/x/protection/required_status_checks":   "never allows reading",
		"/repos/acme/widgets/branches/main/protection/required_pull_request_reviews": "never allows reading",
	}
	for target, want := range refused {
		_, err := ClassifyREST("GET", target, nil, nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error with %q", target, err, want)
		}
	}
	allowed := []string{
		"/repos/acme/widgets/compare/main...feature/x",
		"/repos/acme/widgets/compare/" + sha + "..." + sha,
		"/repos/acme/widgets/commits/" + sha,
		"/repos/acme/widgets/commits/main/status",
		"/repos/acme/widgets/git/trees/" + sha,
		"/repos/acme/widgets/branches/feature/x",
		"/repos/acme/widgets/contents/README.md?ref=main",
		"/repos/acme/widgets/issues/1/events",
	}
	for _, target := range allowed {
		if _, err := ClassifyREST("GET", target, nil, nil); err != nil {
			t.Errorf("%s: %v", target, err)
		}
	}
}

// Every JSON read gets clone tokens stripped, except file contents and
// storage redirects.
func TestRESTStripsCloneTokens(t *testing.T) {
	for target, want := range map[string]bool{
		"/repos/acme/widgets":                         true,
		"/repos/acme/widgets/pulls":                   true,
		"/repos/acme/widgets/pulls/3":                 true,
		"/repos/acme/widgets/actions/runs/1":          true,
		"/repos/acme/widgets/contents/a/b.go":         false,
		"/repos/acme/widgets/git/blobs/" + sha:        false,
		"/repos/acme/widgets/actions/runs/1/logs":     false,
		"/repos/acme/widgets/actions/artifacts/2/zip": false,
	} {
		r, err := ClassifyREST("GET", target, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if got := len(r.Strip) > 0; got != want {
			t.Errorf("%s: strips %v, want %v", target, got, want)
		}
	}
}

func TestGraphQLReadsStayInRepo(t *testing.T) {
	refused := map[string]struct {
		body []byte
		want string
	}{
		"user search":                     {gql(`query($q:String!){search(query:$q,type:USER,first:5){nodes{... on User{repositories(first:5){nodes{name}}}}}}`, map[string]any{"q": "repo:acme/widgets"}), "type ISSUE"},
		"repo search":                     {gql(`query($q:String!){search(query:$q,type:REPOSITORY,first:5){repositoryCount}}`, map[string]any{"q": "repo:acme/widgets"}), "type ISSUE"},
		"follow renames":                  {gql(`{repository(owner:"acme",name:"widgets",followRenames:true){name}}`, nil), "followRenames: false"},
		"renames variable":                {gql(`query($f:Boolean!){repository(owner:"acme",name:"widgets",followRenames:$f){name}}`, map[string]any{"f": false}), "followRenames: false"},
		"deploy keys":                     {gql(`{repository(owner:"acme",name:"widgets"){deployKeys(first:5){nodes{key}}}}`, nil), "Repository.deployKeys"},
		"rulesets":                        {gql(`{repository(owner:"acme",name:"widgets"){rulesets(first:5){nodes{name}}}}`, nil), "Repository.rulesets"},
		"codeowners":                      {gql(`{repository(owner:"acme",name:"widgets"){codeowners{errors{kind}}}}`, nil), "Repository.codeowners"},
		"interaction limits":              {gql(`{repository(owner:"acme",name:"widgets"){interactionAbility{limit}}}`, nil), "Repository.interactionAbility"},
		"protection rules":                {gql(`{repository(owner:"acme",name:"widgets"){branchProtectionRules(first:5){nodes{pattern}}}}`, nil), "Repository.branchProtectionRules"},
		"custom properties":               {gql(`{repository(owner:"acme",name:"widgets"){repositoryCustomPropertyValues(first:5){nodes{propertyName value}}}}`, nil), "Repository.repositoryCustomPropertyValues"},
		"environment protection":          {gql(`{repository(owner:"acme",name:"widgets"){environment(name:"production"){protectionRules(first:5){nodes{timeout}}}}}`, nil), "Environment.protectionRules"},
		"protection beyond the one field": {gql(`{repository(owner:"acme",name:"widgets"){pullRequest(number:1){baseRef{branchProtectionRule{pattern}}}}}`, nil), "BranchProtectionRule.pattern"},
		"short SHA object":                {gql(`{repository(owner:"acme",name:"widgets"){object(expression:"abc1234:README.md"){id}}}`, nil), "full SHA"},
		"short SHA in an expression":      {gql(`{repository(owner:"acme",name:"widgets"){object(expression:"abc1234~0:README.md"){id}}}`, nil), "full SHA"},
		"peeled short SHA":                {gql(`{repository(owner:"acme",name:"widgets"){object(expression:"abc1234^{commit}"){id}}}`, nil), "full SHA"},
		"message search":                  {gql(`{repository(owner:"acme",name:"widgets"){object(expression:":/fix"){id}}}`, nil), "before the colon"},
		"short oid":                       {gql(`{repository(owner:"acme",name:"widgets"){object(oid:"abc1234"){id}}}`, nil), "full SHA"},
		"linked issue's repo issues":      {gql(`{repository(owner:"acme",name:"widgets"){issue(number:1){parent{repository{issues(first:1){nodes{body}}}}}}}`, nil), "Repository.issues"},
		"linked issue's repo code":        {gql(`{repository(owner:"acme",name:"widgets"){issue(number:1){parent{repository{object(expression:"HEAD:README"){id}}}}}}`, nil), "Repository.object"},
		"viewer's repo by name":           {gql(`{viewer{repository(name:"secret"){defaultBranchRef{name}}}}`, nil), "User.repository"},
	}
	for name, c := range refused {
		_, err := ClassifyGraphQL(c.body, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, c.want)
		}
	}

	allowed := map[string]struct {
		body          []byte
		want, wantNot string
	}{
		// GitHub would otherwise answer for whatever the repo was renamed to.
		"pins renames":                    {gql(`{repository(owner:"acme",name:"widgets"){name}}`, nil), "followRenames: false", ""},
		"renames off":                     {gql(`{repository(owner:"acme",name:"widgets",followRenames:false){name}}`, nil), "followRenames: false", ""},
		"linked issue's repo description": {gql(`{repository(owner:"acme",name:"widgets"){issue(number:1){parent{repository{nameWithOwner description}}}}}`, nil), "description", ""},
		"linked issue's repo name":        {gql(`{repository(owner:"acme",name:"widgets"){issue(number:1){parent{repository{nameWithOwner}}}}}`, nil), "nameWithOwner", ""},
		"strict checks":                   {gql(`{repository(owner:"acme",name:"widgets"){pullRequest(number:1){baseRef{branchProtectionRule{requiresStrictStatusChecks}}}}}`, nil), "requiresStrictStatusChecks", ""},
		"full SHA object":                 {gql(`{repository(owner:"acme",name:"widgets"){object(expression:"`+sha+`:README.md"){id}}}`, nil), sha, ""},
		"branch object":                   {gql(`{repository(owner:"acme",name:"widgets"){object(expression:"main:README.md"){id}}}`, nil), "main:README.md", ""},
	}
	for name, c := range allowed {
		g, err := ClassifyGraphQL(c.body, nil)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !strings.Contains(string(g.Body), c.want) || (c.wantNot != "" && strings.Contains(string(g.Body), c.wantNot)) {
			t.Errorf("%s: forwards %s", name, g.Body)
		}
		if _, err := ClassifyGraphQL(g.Body, nil); err != nil {
			t.Errorf("%s: printed request no longer classifies: %v", name, err)
		}
	}
}
