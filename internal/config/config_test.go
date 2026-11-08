package config

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
)

func TestAllowed(t *testing.T) {
	c := &Config{
		Token: &Token{Secret: "file:/x", Source: "pat"},
		SSH:   &Key{Key: "file:/y"},
		Repos: []Repo{
			{Match: "acme/*", Via: "ssh"},
			{Match: "acme/payments", Access: "read"},
			{Match: "mbriggs/*"},
		},
	}
	cases := []struct {
		repo  string
		ok    bool
		write bool
		via   string
	}{
		{"acme/widgets", true, true, "ssh"},
		{"ACME/Payments", true, false, "https"},
		{"mbriggs/dots", true, true, "https"},
		{"acmex/foo", false, false, ""},
		{"other/repo", false, false, ""},
	}
	for _, tc := range cases {
		r, _ := github.ParseRepo(tc.repo)
		got, ok := c.Allowed(r)
		if ok != tc.ok || got.Write != tc.write || got.Via != tc.via {
			t.Errorf("Allowed(%s) = %+v, %v", tc.repo, got, ok)
		}
	}
	if o := c.SSHOwners(); len(o) != 1 || o[0] != "acme" {
		t.Errorf("SSHOwners = %v", o)
	}

	sshOnly := &Config{SSH: &Key{Key: "file:/y"}, Repos: []Repo{{Match: "acme/*"}}}
	if r, _ := sshOnly.Allowed(github.Repo{Owner: "acme", Name: "x"}); r.Via != "ssh" {
		t.Errorf("SSH-only machine routes %q", r.Via)
	}
}

func TestWriteLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hallpass.toml")
	if c, err := Load(path); err != nil || c.Token != nil {
		t.Fatalf("missing file: %+v, %v", c, err)
	}
	c := &Config{UIDs: []uint32{1000}, Repos: []Repo{{Match: "acme/*"}}}
	if err := c.Write(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || len(got.Repos) != 1 || got.UIDs[0] != 1000 {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	for _, bad := range []*Config{
		{Repos: []Repo{{Match: "acme"}}},
		{Allow: []op.Op{"pr.mrege"}},
		{Repos: []Repo{{Match: "acme/x", Deny: []op.Op{"nope"}}}},
		{Allow: []op.Op{op.Labels}, Deny: []op.Op{op.Labels}},
	} {
		if err := bad.Write(path); err == nil {
			t.Errorf("wrote %+v", bad)
		}
	}
}

func TestPolicyLayers(t *testing.T) {
	c := &Config{
		Allow: []op.Op{op.WorkflowRerun, op.Labels},
		Deny:  []op.Op{op.IssueCreate},
		Repos: []Repo{
			{Match: "acme/*", Deny: []op.Op{op.Labels}},
			{Match: "acme/site", Allow: []op.Op{op.PushDefault, op.Labels}},
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
