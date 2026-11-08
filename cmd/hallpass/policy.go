package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/system"
)

const policyUsage = `usage:
  hallpass policy show [OWNER/REPO]
  sudo hallpass policy allow|deny|reset OP... [--repo OWNER/REPO|OWNER/*]`

func policyCmd(args []string) error {
	if len(args) == 0 {
		return errors.New(policyUsage)
	}
	switch args[0] {
	case "show":
		return policyShow(args[1:])
	case "allow", "deny", "reset":
		return policyEdit(args[0], args[1:])
	}
	return errors.New(policyUsage)
}

func policyEdit(verb string, args []string) error {
	fs := flag.NewFlagSet("policy "+verb, flag.ExitOnError)
	repo := fs.String("repo", "", "change one allowlist entry instead of every repo")
	fs.Parse(reorder(args, "--repo"))
	if fs.NArg() == 0 {
		return errors.New(policyUsage)
	}
	var ops []op.Op
	for _, name := range fs.Args() {
		if _, ok := op.Lookup(name); !ok {
			return fmt.Errorf("no operation is named %q. hallpass policy show lists them", name)
		}
		ops = append(ops, op.Op(name))
	}
	match := ""
	if *repo != "" {
		m, err := normalizeMatch(*repo)
		if err != nil {
			return err
		}
		match = m
	}
	if err := system.RequireRoot("policy " + verb); err != nil {
		return err
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		return err
	}
	if err := editPolicy(cfg, verb, match, ops); err != nil {
		return err
	}
	if err := commit(cfg); err != nil {
		return err
	}

	where := "every repo"
	if match != "" {
		where = match
	}
	for _, o := range ops {
		info, _ := op.Lookup(string(o))
		switch verb {
		case "allow":
			fmt.Fprintf(os.Stderr, "Agents may now %s in %s.\n", info.Does, where)
			if info.Warn != "" {
				fmt.Fprintln(os.Stderr, "  "+info.Warn)
			}
		case "deny":
			fmt.Fprintf(os.Stderr, "Agents may no longer %s in %s.\n", info.Does, where)
		case "reset":
			fmt.Fprintf(os.Stderr, "%s in %s now follows the broader setting.\n", o, where)
		}
		for _, e := range overriding(cfg, match, o) {
			fmt.Fprintf(os.Stderr, "  %s has its own setting for %s, which still applies there.\n", e, o)
		}
	}
	return nil
}

// editPolicy changes one layer of cfg: the global lists when match is "",
// else the allowlist entry with that match.
func editPolicy(cfg *config.Config, verb, match string, ops []op.Op) error {
	allow, deny := &cfg.Allow, &cfg.Deny
	if match != "" {
		i := slices.IndexFunc(cfg.Repos, func(r config.Repo) bool { return strings.EqualFold(r.Match, match) })
		if i < 0 {
			return fmt.Errorf("%s isn't in the allowlist. Allow it first: sudo %s allow %s", match, system.Binary, match)
		}
		allow, deny = &cfg.Repos[i].Allow, &cfg.Repos[i].Deny
	}
	for _, o := range ops {
		*allow = slices.DeleteFunc(*allow, func(x op.Op) bool { return x == o })
		*deny = slices.DeleteFunc(*deny, func(x op.Op) bool { return x == o })
		switch verb {
		case "allow":
			*allow = append(*allow, o)
		case "deny":
			*deny = append(*deny, o)
		}
	}
	return nil
}

// overriding lists the entries more specific than the layer at match that
// name o, so their setting wins over the one just changed.
func overriding(cfg *config.Config, match string, o op.Op) []string {
	owner, name, _ := strings.Cut(match, "/")
	var out []string
	for _, r := range cfg.Repos {
		rOwner, rName, _ := strings.Cut(r.Match, "/")
		narrower := match == "" || (name == "*" && rName != "*" && strings.EqualFold(rOwner, owner))
		if narrower && (slices.Contains(r.Allow, o) || slices.Contains(r.Deny, o)) {
			out = append(out, r.Match)
		}
	}
	return out
}

func policyShow(args []string) error {
	if len(args) > 1 {
		return errors.New(policyUsage)
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if len(args) == 0 {
		fmt.Fprintln(tw, "OPERATION\tDEFAULT\tGLOBAL\tAGENTS MAY")
		for _, info := range op.All {
			global := ""
			switch {
			case slices.Contains(cfg.Allow, info.Op):
				global = "allow"
			case slices.Contains(cfg.Deny, info.Op):
				global = "deny"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", info.Op, onOff(info.On), global, info.Does)
		}
		tw.Flush()
		for _, r := range cfg.Repos {
			if len(r.Allow)+len(r.Deny) == 0 {
				continue
			}
			fmt.Printf("\n%s:", r.Match)
			for _, o := range r.Allow {
				fmt.Printf(" +%s", o)
			}
			for _, o := range r.Deny {
				fmt.Printf(" -%s", o)
			}
		}
		fmt.Println()
		fmt.Println("Hard denies, like secrets, settings, and workflow edits, aren't operations, so no policy allows them.")
		return nil
	}

	repo, err := github.ParseRepo(strings.TrimPrefix(strings.TrimPrefix(args[0], "https://github.com/"), "github.com/"))
	if err != nil {
		return err
	}
	ds, ok := cfg.Decide(repo)
	if !ok {
		return fmt.Errorf("%s isn't in the allowlist, so agents can't reach it", repo)
	}
	if rule, _ := cfg.Allowed(repo); !rule.Write {
		fmt.Printf("Agents may only read %s, so it refuses every write below.\n\n", repo)
	}
	fmt.Fprintln(tw, "OPERATION\tIN EFFECT\tSET BY\tAGENTS MAY")
	for _, d := range ds {
		info, _ := op.Lookup(string(d.Op))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", d.Op, onOff(d.On), d.From, info.Does)
	}
	return tw.Flush()
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
