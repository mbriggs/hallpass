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
		{Match: "acme/site", Deny: []op.Op{op.PRMerge}},
		{Match: "mbriggs/dots"},
	}}
	if err := editPolicy(cfg, "allow", "", []op.Op{op.PRMerge, op.Labels}); err != nil {
		t.Fatal(err)
	}
	// Denying moves an operation out of the allow list.
	if err := editPolicy(cfg, "deny", "", []op.Op{op.Labels}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Allow, []op.Op{op.PRMerge}) || !slices.Equal(cfg.Deny, []op.Op{op.Labels}) {
		t.Errorf("global: allow %v deny %v", cfg.Allow, cfg.Deny)
	}
	if err := editPolicy(cfg, "allow", "acme/site", []op.Op{op.PRMerge}); err != nil {
		t.Fatal(err)
	}
	if err := editPolicy(cfg, "reset", "acme/site", []op.Op{op.PRMerge}); err != nil {
		t.Fatal(err)
	}
	if site := cfg.Repos[1]; len(site.Allow)+len(site.Deny) != 0 {
		t.Errorf("reset left %+v", site)
	}
	if err := editPolicy(cfg, "allow", "acme/nope", []op.Op{op.PRMerge}); err == nil {
		t.Error("edited an entry that isn't in the allowlist")
	}
	if err := cfg.Validate(); err != nil {
		t.Error(err)
	}

	cfg.Repos[1].Deny = []op.Op{op.PRMerge}
	if got := overriding(cfg, "", op.PRMerge); !slices.Equal(got, []string{"acme/site"}) {
		t.Errorf("overriding global = %v", got)
	}
	if got := overriding(cfg, "acme/*", op.PRMerge); !slices.Equal(got, []string{"acme/site"}) {
		t.Errorf("overriding acme/* = %v", got)
	}
	if got := overriding(cfg, "acme/site", op.PRMerge); len(got) != 0 {
		t.Errorf("overriding an exact entry = %v", got)
	}
}
