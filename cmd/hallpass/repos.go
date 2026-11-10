package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/system"
)

// allowEntry adds an allowlist entry for match, or sets the access of the
// one there. Allowing a repo again changes its access, not its policy or
// protected paths.
func allowEntry(cfg *config.Config, match string, read bool) {
	access := ""
	if read {
		access = "read"
	}
	for i, r := range cfg.Repos {
		if strings.EqualFold(r.Match, match) {
			cfg.Repos[i].Match, cfg.Repos[i].Access = match, access
			return
		}
	}
	cfg.Repos = append(cfg.Repos, config.Repo{Match: match, Access: access})
}

func allow(args []string) error {
	fs := flag.NewFlagSet("allow", flag.ExitOnError)
	read := fs.Bool("read", false, "agents may read but not write")
	fs.Parse(reorder(args))
	if fs.NArg() != 1 {
		return errors.New("usage: hallpass allow OWNER/REPO|OWNER/* [--read]")
	}
	if err := system.RequireRoot("allow"); err != nil {
		return err
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		return err
	}
	match, err := normalizeMatch(fs.Arg(0))
	if err != nil {
		return err
	}
	allowEntry(cfg, match, *read)
	if err := commit(cfg); err != nil {
		return err
	}
	access := "read and write"
	if *read {
		access = "read"
	}
	fmt.Fprintf(os.Stderr, "Agents may now %s %s.\n", access, match)
	if before, ok := strings.CutSuffix(match, "/*"); ok {
		fmt.Fprintln(os.Stderr, "That covers every current and future repo of "+before+".")
	}
	return nil
}

func disallow(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: hallpass disallow OWNER/REPO|OWNER/*")
	}
	if err := system.RequireRoot("disallow"); err != nil {
		return err
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		return err
	}
	match, err := normalizeMatch(args[0])
	if err != nil {
		return err
	}
	kept := cfg.Repos[:0]
	for _, r := range cfg.Repos {
		if !strings.EqualFold(r.Match, match) {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(cfg.Repos) {
		return fmt.Errorf("%s isn't in the allowlist", match)
	}
	cfg.Repos = kept
	if err := commit(cfg); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Removed %s. A broader entry, like OWNER/*, may still cover it.\n", match)
	return nil
}

func normalizeMatch(s string) (string, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://github.com/"), "github.com/")
	if owner, ok := strings.CutSuffix(s, "/*"); ok {
		if _, err := github.ParseRepo(owner + "/x"); err != nil {
			return "", err
		}
		return owner + "/*", nil
	}
	r, err := github.ParseRepo(s)
	if err != nil {
		return "", err
	}
	return r.String(), nil
}

// reorder moves flags ahead of the positional arguments, so both
// "allow acme/x --read" and "allow --read acme/x" work. valued names the
// flags that take a value.
func reorder(args []string, valued ...string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case slices.Contains(valued, a) && i+1 < len(args):
			flags = append(flags, a, args[i+1])
			i++
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)
		default:
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}
