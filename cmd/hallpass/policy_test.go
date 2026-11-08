package main

import (
	"slices"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/op"
)

func TestEditPolicy(t *testing.T) {
	cfg := &config.Config{Repos: []config.Repo{
		{Match: "acme/*"},
		{Match: "acme/site", Deny: []config.Grant{config.Grant(op.PRMerge)}},
		{Match: "mbriggs/dots"},
	}}
	if _, err := editPolicy(cfg, "allow", "", []config.Grant{config.Grant(op.PRMerge), config.Grant(op.Labels)}); err != nil {
		t.Fatal(err)
	}
	// Denying moves an operation out of the allow list.
	if _, err := editPolicy(cfg, "deny", "", []config.Grant{config.Grant(op.Labels)}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Allow, []config.Grant{config.Grant(op.PRMerge)}) || !slices.Equal(cfg.Deny, []config.Grant{config.Grant(op.Labels)}) {
		t.Errorf("global: allow %v deny %v", cfg.Allow, cfg.Deny)
	}
	if _, err := editPolicy(cfg, "allow", "acme/site", []config.Grant{config.Grant(op.PRMerge)}); err != nil {
		t.Fatal(err)
	}
	if _, err := editPolicy(cfg, "reset", "acme/site", []config.Grant{config.Grant(op.PRMerge)}); err != nil {
		t.Fatal(err)
	}
	if site := cfg.Repos[1]; len(site.Allow)+len(site.Deny) != 0 {
		t.Errorf("reset left %+v", site)
	}
	if _, err := editPolicy(cfg, "allow", "other/nope", []config.Grant{config.Grant(op.PRMerge)}); err == nil {
		t.Error("edited an entry that isn't in the allowlist")
	}
	if err := cfg.Validate(); err != nil {
		t.Error(err)
	}
}

func TestEditPolicyAddsEntryUnderOwner(t *testing.T) {
	cfg := &config.Config{Repos: []config.Repo{{Match: "acme/*", Access: "read"}}}
	if _, err := editPolicy(cfg, "reset", "acme/site", []config.Grant{config.Grant(op.PRMerge)}); err == nil {
		t.Error("reset added an entry with nothing to reset")
	}
	added, err := editPolicy(cfg, "deny", "acme/site", []config.Grant{config.Grant(op.PRMerge)})
	if err != nil || !added {
		t.Fatalf("added %v, err %v", added, err)
	}
	// The new entry keeps the read access acme/* gives, since an exact
	// entry's access wins.
	site := cfg.Repos[1]
	if site.Match != "acme/site" || site.Access != "read" || !slices.Equal(site.Deny, []config.Grant{config.Grant(op.PRMerge)}) {
		t.Errorf("added %+v", site)
	}
	if added, _ := editPolicy(cfg, "allow", "acme/site", []config.Grant{config.Grant(op.Labels)}); added || len(cfg.Repos) != 2 {
		t.Errorf("added a second entry: %+v", cfg.Repos)
	}
	if _, err := editPolicy(cfg, "allow", "other/site", []config.Grant{config.Grant(op.PRMerge)}); err == nil {
		t.Error("added an entry no OWNER/* covers")
	}
}
