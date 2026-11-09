package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/policy"
)

func TestAllowed(t *testing.T) {
	c := &Config{
		Token: &Token{Secret: "file:/x", Source: "pat"},
		SSH:   &Key{Key: "file:/y"},
		Repos: []Repo{
			{Match: "acme/*"},
			{Match: "acme/payments", Access: "read"},
			{Match: "mbriggs/*"},
		},
	}
	cases := []struct {
		repo  string
		ok    bool
		write bool
	}{
		{"acme/widgets", true, true},
		{"ACME/Payments", true, false},
		{"mbriggs/dots", true, true},
		{"acmex/foo", false, false},
		{"other/repo", false, false},
	}
	for _, tc := range cases {
		r, _ := github.ParseRepo(tc.repo)
		got, ok := c.Allowed(r)
		if ok != tc.ok || got.Write != tc.write {
			t.Errorf("Allowed(%s) = %+v, %v", tc.repo, got, ok)
		}
	}
}

// A config written before via went away still loads.
func TestLoadIgnoresVia(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hallpass.toml")
	os.WriteFile(path, []byte("[[repo]]\nmatch = \"mbriggs/*\"\nvia = \"ssh\"\n"), 0o644)
	c, err := Load(path)
	if err != nil || len(c.Repos) != 1 {
		t.Fatalf("Load = %+v, %v", c, err)
	}
}

func TestWriteLoad(t *testing.T) {
	// Write creates the directory, as it does /etc/hallpass on a first
	// install.
	path := filepath.Join(t.TempDir(), "etc", "hallpass.toml")
	if c, err := Load(path); err != nil || c.Token != nil {
		t.Fatalf("missing file: %+v, %v", c, err)
	}
	c := &Config{
		UIDs:    []uint32{1000},
		Token:   &Token{Secret: "tpm:/x", Source: "pat"},
		SSH:     &Key{Key: "file:/y"},
		Signing: &Key{Key: "file:/z"},
		Repos:   []Repo{{Match: "acme/*"}, {Match: "acme/site", Access: "read"}, {Match: "acme/api", Access: "write"}},
	}
	if err := c.Write(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || len(got.Repos) != 3 || got.UIDs[0] != 1000 {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	for _, bad := range []*Config{
		{Token: &Token{Secret: "/x", Source: "pat"}},
		{Token: &Token{Secret: "tpm:/x", Source: "paste"}},
		{SSH: &Key{Key: "y"}},
		{Repos: []Repo{{Match: "acme/x", Access: "admin"}}},
		{Repos: []Repo{{Match: "acme"}}},
		{Allow: []Grant{"pr.mrege"}},
		{Repos: []Repo{{Match: "acme/x", Deny: []Grant{"nope"}}}},
		{Allow: []Grant{Grant(op.Labels)}, Deny: []Grant{Grant(op.Labels)}},
		{Allow: []Grant{"read:actions/secrets"}},
		{Allow: []Grant{"field:Repository.tempCloneToken"}},
		{Allow: []Grant{"field:Repository.issues"}},
		{Allow: []Grant{"nope:x"}},
		{Repos: []Repo{{Match: "acme/x", Allow: []Grant{"field:Repository.hasProjectsEnabled"}}}},
	} {
		if err := bad.Write(path); err == nil {
			t.Errorf("wrote %+v", bad)
		}
	}
	// A missing SSH key mustn't end the walk before the signing key.
	if err := (&Config{Signing: &Key{Key: "z"}}).Validate(); err == nil {
		t.Fatal("a bad signing key passed when there's no SSH key")
	}
}

func TestPolicyLayers(t *testing.T) {
	c := &Config{
		Allow: []Grant{Grant(op.WorkflowRerun), Grant(op.Labels)},
		Deny:  []Grant{Grant(op.IssueCreate)},
		Repos: []Repo{
			{Match: "acme/*", Deny: []Grant{Grant(op.Labels)}},
			{Match: "acme/site", Allow: []Grant{Grant(op.PushDefault), Grant(op.Labels)}},
			{Match: "mbriggs/dots"},
		},
	}
	cases := []struct {
		repo string
		o    op.Op
		on   bool
		from string
	}{
		{"mbriggs/dots", op.PRCreate, true, "default"},
		{"mbriggs/dots", op.PRMerge, false, "default"},
		{"mbriggs/dots", op.Assign, false, "default"},
		{"mbriggs/dots", op.WorkflowRerun, true, "global"},
		{"mbriggs/dots", op.IssueCreate, false, "global"},
		{"mbriggs/dots", op.Labels, true, "global"},
		{"acme/api", op.Labels, false, "acme/*"},
		{"acme/api", op.WorkflowRerun, true, "global"},
		{"acme/site", op.Labels, true, "acme/site"},
		{"acme/site", op.PushDefault, true, "acme/site"},
		{"acme/api", op.PushDefault, false, "default"},
	}
	for _, tc := range cases {
		r, _ := github.ParseRepo(tc.repo)
		ds, ok := c.Decide(r)
		if !ok {
			t.Fatalf("%s isn't covered", tc.repo)
		}
		i := slices.IndexFunc(ds, func(d Decision) bool { return d.Op == tc.o })
		if d := ds[i]; d.On != tc.on || d.From != tc.from {
			t.Errorf("%s %s = %+v, want on=%v from %s", tc.repo, tc.o, d, tc.on, tc.from)
		}
		rule, _ := c.Allowed(r)
		if rule.Ops.Has(tc.o) != tc.on {
			t.Errorf("%s: Allowed disagrees with Decide on %s", tc.repo, tc.o)
		}
	}
}

// API grants sit in the same lists as operations, survive a write and a
// load, and layer the way operations do.
func TestAPIGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hallpass.toml")
	in := &Config{
		Allow: []Grant{Grant(op.Labels), "read:deployments", "field:Repository.hasProjectsEnabled"},
		Deny:  []Grant{"field:Repository.description"},
		Repos: []Repo{
			{Match: "acme/*", Deny: []Grant{"read:deployments"}},
			{Match: "acme/site", Allow: []Grant{"read:deployments"}, Deny: []Grant{"read:actions/runs/#/logs"}},
			{Match: "mbriggs/dots"},
		},
	}
	if err := in.Write(path); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Allow, in.Allow) || !slices.Equal(c.Repos[1].Deny, in.Repos[1].Deny) {
		t.Fatalf("round trip: %+v", c)
	}
	if rule, _ := c.Allowed(github.Repo{Owner: "mbriggs", Name: "dots"}); !rule.Ops.Has(op.Labels) {
		t.Errorf("API grants disturbed the operations")
	}
	g := c.Grants()
	if !g.Fields["Repository.hasProjectsEnabled"] || g.Fields["Repository.description"] {
		t.Errorf("fields = %v", g.Fields)
	}
	for _, tc := range []struct {
		repo, path string
		ok         bool
	}{
		{"mbriggs/dots", "deployments", true},       // global allow
		{"acme/api", "deployments", false},          // acme/* deny beats global
		{"acme/site", "deployments", true},          // exact allow beats acme/*
		{"acme/site", "actions/runs/5/logs", false}, // exact deny of a built-in
		{"acme/api", "actions/runs/5/logs", true},   // the built-in elsewhere
	} {
		_, err := policy.ClassifyREST("GET", "/repos/"+tc.repo+"/"+tc.path, nil, g)
		if tc.ok != (err == nil) {
			t.Errorf("%s %s: err = %v", tc.repo, tc.path, err)
		}
	}
}
