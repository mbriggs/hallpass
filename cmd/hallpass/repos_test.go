package main

import (
	"slices"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/op"
)

// Allowing a repo again changes its access and keeps the rest of its entry.
func TestAllowEntryKeepsPolicyAndPaths(t *testing.T) {
	cfg := &config.Config{Repos: []config.Repo{{
		Match:          "acme/site",
		Allow:          []config.Grant{config.Grant(op.PRMerge)},
		ProtectedPaths: []string{"scripts/deploy.sh"},
	}}}
	allowEntry(cfg, "acme/site", true)
	allowEntry(cfg, "acme/other", false)
	site := cfg.Repos[0]
	if len(cfg.Repos) != 2 || site.Access != "read" || !slices.Equal(site.ProtectedPaths, []string{"scripts/deploy.sh"}) || len(site.Allow) != 1 {
		t.Errorf("after allow: %+v", cfg.Repos)
	}
}
