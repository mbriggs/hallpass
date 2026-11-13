package policy

import (
	"regexp"
	"slices"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"

	"github.com/mbriggs/hallpass/internal/github"
)

// Grants are what the config adds to or removes from the built-in tables,
// so a user can open a read gh needs without a rebuild. Config never adds
// writes: each write needs an operation, a list of body keys, and often an
// author check, and those live in code.
//
// The zero value, and a nil *Grants, mean the built-in tables alone.
type Grants struct {
	// Fields decides fields read of an object that may be outside the
	// repo a request named, keyed "Type.field": true allows one, false
	// denies one. A missing key follows the built-in tables.
	Fields map[string]bool
	// Reads returns the layers of read routes for repo, broadest first.
	// The last layer that matches a path decides it.
	Reads func(github.Repo) []ReadLayer
}

// ReadLayer is one layer of the config's read routes, like the global
// lists or one allowlist entry's. Within a layer, deny wins.
type ReadLayer struct {
	From        string
	Allow, Deny []string
}

// fieldOn reports whether an identity read may see key, and whether the
// config decided it.
func (g *Grants) fieldOn(key string) (on, set bool) {
	if g == nil {
		return false, false
	}
	on, set = g.Fields[key]
	return on, set
}

// readOn reports whether the config's layers decide a GET of rest in repo,
// starting from the built-in verdict. from names the deciding layer.
func (g *Grants) readOn(repo github.Repo, rest []string, builtin bool) (on bool, from string) {
	on, from = builtin, "default"
	if g == nil || g.Reads == nil {
		return on, from
	}
	for _, l := range g.Reads(repo) {
		switch {
		case anyMatch(rest, l.Deny):
			on, from = false, l.From
		case anyMatch(rest, l.Allow):
			on, from = true, l.From
		}
	}
	return on, from
}

func anyMatch(rest []string, pats []string) bool {
	for _, p := range pats {
		if match(rest, p) {
			return true
		}
	}
	return false
}

// literal is a fixed segment of a config read pattern. GitHub's REST paths
// are lowercase.
var literal = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// readFloor lists the routes under /repos/{owner}/{repo} that no config
// opens: secrets and their names, settings, keys, hooks, and security
// findings. Each covers its path and everything under it. Actions
// variables and rulesets aren't here: they're refused by default, and
// config may open them.
var readFloor = []string{
	"secrets", "actions/secrets", "actions/permissions",
	"actions/runners", "actions/oidc", "actions/organization-secrets",
	"environments/*/secrets", "environments/*/variables",
	"dependabot", "codespaces", "hooks", "keys", "invitations",
	"secret-scanning", "code-scanning", "vulnerability-alerts", "private-vulnerability-reporting",
	"security-advisories", "interaction-limits", "autolinks", "properties",
}

// floored reports whether a request path falls under the read floor.
func floored(rest []string) bool {
	for _, f := range readFloor {
		p := strings.Split(f, "/")
		if len(rest) >= len(p) && match(rest[:len(p)], f) {
			return true
		}
	}
	return branchProtection(rest)
}

// branchProtection reports whether a path is a branch's protection
// settings, branches/NAME/protection[/...]. Branch names can hold slashes,
// so any protection segment after the first name counts, and a branch
// with protection in its name can't be read through hallpass.
func branchProtection(segs []string) bool {
	if len(segs) < 3 || segs[0] != "branches" {
		return false
	}
	return slices.Contains(segs[2:], "protection")
}

// overlapsFloor reports whether a config pattern could match a path under
// the read floor.
func overlapsFloor(pat string) bool {
	ps := strings.Split(pat, "/")
	tail := ps[len(ps)-1] == "**"
	if tail {
		ps = ps[:len(ps)-1]
	}
	for _, f := range readFloor {
		fs := strings.Split(f, "/")
		// Without **, the pattern matches paths of exactly its length, so
		// it reaches under f only when it's at least as long.
		if len(ps) < len(fs) && !tail {
			continue
		}
		ok := true
		for i := 0; i < len(fs) && i < len(ps); i++ {
			if !segsMeet(ps[i], fs[i]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	// A branch pattern reaches protection settings when a segment past the
	// branch name could be protection, or ** could cover one.
	if ps[0] == "branches" {
		if tail {
			return true
		}
		for _, s := range ps[min(2, len(ps)):] {
			if s == "protection" || s == "*" {
				return true
			}
		}
	}
	return false
}

// segsMeet reports whether some path segment matches both pattern
// segments. * matches any name, numbers included, so it meets # and every
// literal. # matches numbers, and floor literals aren't numbers.
func segsMeet(a, b string) bool {
	return a == b || a == "*" || b == "*"
}

// CheckRead refuses a config read pattern that's malformed or reaches the
// read floor. Patterns are path segments under /repos/{owner}/{repo}: a
// literal, # for a number, * for one name, and a final ** for the rest of
// the path. The first segment must be a literal.
func CheckRead(pat string) error {
	segs := strings.Split(pat, "/")
	for i, s := range segs {
		switch {
		case s == "#" || s == "*":
			if i == 0 {
				return errorf("read:%s must start with a literal segment, like deployments", pat)
			}
		case s == "**":
			if i == 0 || i != len(segs)-1 {
				return errorf("read:%s may use ** only as its last segment", pat)
			}
		case !literal.MatchString(s):
			return errorf("read:%s: %q isn't a path segment", pat, s)
		}
	}
	if overlapsFloor(pat) {
		return errorf("read:%s reaches secrets, settings, keys, hooks, or security findings, which no policy allows", pat)
	}
	return nil
}

// CheckField refuses a config field that isn't a scalar or enum field of a
// type in the schema, or that no policy may open.
func CheckField(key string) error {
	typ, field, ok := strings.Cut(key, ".")
	if !ok {
		return errorf("field:%s: want Type.field, like Repository.hasProjectsEnabled", key)
	}
	if deniedFields[key] || settingsTypes[typ] || typ == "BranchProtectionRule" {
		return errorf("field:%s is never readable through hallpass", key)
	}
	s, err := Schema()
	if err != nil {
		return err
	}
	d := s.Types[typ]
	if d == nil || (d.Kind != ast.Object && d.Kind != ast.Interface) {
		return errorf("field:%s: GitHub's schema has no object type %s", key, typ)
	}
	f := d.Fields.ForName(field)
	if f == nil {
		return errorf("field:%s: %s has no field %s", key, typ, field)
	}
	if t := s.Types[f.Type.Name()]; t == nil || (t.Kind != ast.Scalar && t.Kind != ast.Enum) {
		return errorf("field:%s leads to another object. Config may open only scalar and enum fields", key)
	}
	return nil
}

// readPattern names a request path as a read pattern, numbers as #, for a
// refusal to quote.
func readPattern(rest []string) string {
	out := make([]string, len(rest))
	for i, s := range rest {
		if number.MatchString(s) {
			s = "#"
		}
		out[i] = s
	}
	return strings.Join(out, "/")
}
