package main

import (
	"bufio"
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
	"golang.org/x/term"
)

const policyUsage = `usage:
  hallpass policy show [OWNER/REPO]
  sudo hallpass policy allow|deny|reset NAME... [--repo OWNER/REPO|OWNER/*]

NAME is an operation, like pr.merge, or an API read:
  field:Type.field   a field reads may see of a repo or account outside the
                     one a request named, like field:Repository.hasProjectsEnabled.
                     Applies to every repo, so it takes no --repo.
  read:PATTERN       a GET route under /repos/{owner}/{repo}, like
                     read:deployments/#. # is a number, * one name, and a
                     final ** the rest of the path.
A refusal names the NAME that would allow it.`

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
	var grants []config.Grant
	for _, name := range fs.Args() {
		g := config.Grant(name)
		if err := g.Check(); err != nil {
			return err
		}
		if _, ok := g.Field(); ok && *repo != "" {
			return fmt.Errorf("%s applies to every repo; drop --repo", g)
		}
		grants = append(grants, g)
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
	added, err := editPolicy(cfg, verb, match, grants)
	if err != nil {
		return err
	}
	removed := verb == "reset" && offerRemove(cfg, match)
	if err := commit(cfg); err != nil {
		return err
	}
	if added {
		fmt.Fprintf(os.Stderr, "Added %s to the allowlist, with the access %s gives it, to hold its policy.\n", match, wildcard(match))
	}

	where := "every repo"
	if match != "" {
		where = match
	}
	for _, g := range grants {
		does := describe(g)
		switch verb {
		case "allow":
			fmt.Fprintf(os.Stderr, "Agents may now %s in %s.\n", does, where)
			if o, ok := g.Op(); ok {
				if info, _ := op.Lookup(string(o)); info.Warn != "" {
					fmt.Fprintln(os.Stderr, "  "+info.Warn)
				}
			}
		case "deny":
			fmt.Fprintf(os.Stderr, "Agents may no longer %s in %s.\n", does, where)
		case "reset":
			fmt.Fprintf(os.Stderr, "%s in %s now follows the broader setting. hallpass policy show OWNER/REPO shows what applies.\n", g, where)
		}
	}
	if removed {
		fmt.Fprintf(os.Stderr, "Removed %s from the allowlist. %s still covers it.\n", match, wildcard(match))
	}
	return nil
}

// describe completes "agents may ..." for a grant.
func describe(g config.Grant) string {
	if f, ok := g.Field(); ok {
		return "read " + f + " of repos and accounts outside the one a request names"
	}
	if r, ok := g.Read(); ok {
		return "read repos/{repo}/" + r
	}
	o, _ := g.Op()
	info, _ := op.Lookup(string(o))
	return info.Does
}

// editPolicy changes one layer of cfg: the global lists when match is "",
// else the allowlist entry with that match. A repo with no entry of its own
// gets one when OWNER/* covers it, with the same access, and added reports
// that.
func editPolicy(cfg *config.Config, verb, match string, grants []config.Grant) (added bool, err error) {
	allow, deny := &cfg.Allow, &cfg.Deny
	if match != "" {
		i := entry(cfg, match)
		if i < 0 {
			w := entry(cfg, wildcard(match))
			if w < 0 || verb == "reset" {
				return false, fmt.Errorf("%s isn't in the allowlist. Allow it first: sudo %s allow %s", match, system.Binary, match)
			}
			cfg.Repos = append(cfg.Repos, config.Repo{Match: match, Access: cfg.Repos[w].Access})
			i, added = len(cfg.Repos)-1, true
		}
		allow, deny = &cfg.Repos[i].Allow, &cfg.Repos[i].Deny
	}
	for _, g := range grants {
		*allow = slices.DeleteFunc(*allow, func(x config.Grant) bool { return x == g })
		*deny = slices.DeleteFunc(*deny, func(x config.Grant) bool { return x == g })
		switch verb {
		case "allow":
			*allow = append(*allow, g)
		case "deny":
			*deny = append(*deny, g)
		}
	}
	return added, nil
}

// offerRemove asks whether to drop the entry at match once it holds no
// policy and OWNER/* gives the same access, so removing it changes nothing.
// It removes the entry from cfg if the answer is yes.
func offerRemove(cfg *config.Config, match string) bool {
	i, w := entry(cfg, match), entry(cfg, wildcard(match))
	if i < 0 || w < 0 || match == wildcard(match) {
		return false
	}
	e := cfg.Repos[i]
	if len(e.Allow)+len(e.Deny) > 0 || e.Access != cfg.Repos[w].Access {
		return false
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "%s has no policy of its own now, and %s covers it. To remove it: sudo %s disallow %s\n", match, wildcard(match), system.Binary, match)
		return false
	}
	fmt.Fprintf(os.Stderr, "%s has no policy of its own now, and %s covers it. Remove it from the allowlist? [Y/n] ", match, wildcard(match))
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "" && a != "y" && a != "yes" {
		return false
	}
	cfg.Repos = slices.Delete(cfg.Repos, i, i+1)
	return true
}

// entry is the index of the allowlist entry with match, or -1.
func entry(cfg *config.Config, match string) int {
	return slices.IndexFunc(cfg.Repos, func(r config.Repo) bool { return strings.EqualFold(r.Match, match) })
}

// wildcard is the OWNER/* match for OWNER/NAME.
func wildcard(match string) string {
	owner, _, _ := strings.Cut(match, "/")
	return owner + "/*"
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
			case slices.Contains(cfg.Allow, config.Grant(info.Op)):
				global = "allow"
			case slices.Contains(cfg.Deny, config.Grant(info.Op)):
				global = "deny"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", info.Op, onOff(info.On), global, info.Does)
		}
		tw.Flush()
		if api := apiChanges("", cfg.Allow, cfg.Deny); api != "" {
			fmt.Printf("\nAPI reads, every repo:%s\n", api)
		}
		for _, r := range cfg.Repos {
			if len(r.Allow)+len(r.Deny) == 0 {
				continue
			}
			fmt.Printf("\n%s:", r.Match)
			for _, g := range r.Allow {
				fmt.Printf(" +%s", g)
			}
			for _, g := range r.Deny {
				fmt.Printf(" -%s", g)
			}
		}
		fmt.Println()
		fmt.Println("Hard denies, like secrets, settings, and workflow edits, aren't operations or API reads, so no policy allows them.")
		return nil
	}

	repo, err := github.ParseRepo(strings.TrimPrefix(strings.TrimPrefix(args[0], "https://github.com/"), "github.com/"))
	if err != nil {
		return err
	}
	ds, ok := cfg.Decide(repo)
	if !ok {
		if cfg.Anonymous(&repo) {
			return fmt.Errorf("%s isn't in the allowlist, so agents can only read what GitHub shows without a token there", repo)
		}
		return fmt.Errorf("%s isn't in the allowlist, and the policy denies anonymous reads, so agents can't reach it", repo)
	}
	if rule, _ := cfg.Allowed(repo); !rule.Write {
		fmt.Printf("Agents may only read %s, so it refuses every write below.\n\n", repo)
	}
	fmt.Fprintln(tw, "OPERATION\tIN EFFECT\tSET BY\tAGENTS MAY")
	for _, d := range ds {
		info, _ := op.Lookup(string(d.Op))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", d.Op, onOff(d.On), d.From, info.Does)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, l := range cfg.Grants().Reads(repo) {
		var line string
		for _, p := range l.Allow {
			line += " +read:" + p
		}
		for _, p := range l.Deny {
			line += " -read:" + p
		}
		if line != "" {
			fmt.Printf("\nAPI reads set by %s:%s", l.From, line)
		}
	}
	if api := apiChanges("field:", cfg.Allow, cfg.Deny); api != "" {
		fmt.Printf("\nAPI fields, every repo:%s", api)
	}
	fmt.Println()
	return nil
}

// apiChanges lists a layer's field: and read: grants, like
// " +read:deployments -field:Repository.description". prefix narrows it to
// one kind.
func apiChanges(prefix string, allow, deny []config.Grant) string {
	var out string
	for _, list := range []struct {
		sign   string
		grants []config.Grant
	}{{"+", allow}, {"-", deny}} {
		for _, g := range list.grants {
			if _, isOp := g.Op(); isOp || !strings.HasPrefix(string(g), prefix) {
				continue
			}
			out += " " + list.sign + string(g)
		}
	}
	return out
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
