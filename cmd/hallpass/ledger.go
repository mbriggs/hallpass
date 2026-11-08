package main

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/sshgate"
	"github.com/mbriggs/hallpass/internal/system"
)

const ledgerUsage = `usage:
  sudo hallpass ledger list OWNER/REPO
  sudo hallpass ledger add OWNER/REPO BRANCH COMMIT`

var fullOID = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ledger shows or extends the record of branches agents may update. Agents
// can update, force-push, or delete only branches they created, and only
// from the commit they last pushed. add lets them work on a branch while it
// points at COMMIT; the push refusal prints the command with the commit.
func ledger(args []string) error {
	if len(args) < 2 {
		return errors.New(ledgerUsage)
	}
	repo, err := github.ParseRepo(args[1])
	if err != nil {
		return err
	}
	path := config.StateDir() + "/branches.jsonl"
	switch {
	case args[0] == "list" && len(args) == 2:
		if err := system.RequireRoot("ledger list"); err != nil {
			return err
		}
		branches := sshgate.OpenLedger(path).Branches(repo)
		for _, b := range slices.Sorted(maps.Keys(branches)) {
			tip := branches[b]
			if tip == "" {
				tip = "(no commit recorded; agents can't update it)"
			}
			fmt.Println(b, tip)
		}
		return nil
	case args[0] == "add" && len(args) == 4:
		if err := system.RequireRoot("ledger add"); err != nil {
			return err
		}
		if !fullOID.MatchString(args[3]) {
			return fmt.Errorf("%q isn't a full commit hash", args[3])
		}
		if err := sshgate.OpenLedger(path).Record(repo, args[2], args[3], "added by hand"); err != nil {
			return err
		}
		if err := ownByService(path); err != nil {
			return err
		}
		if err := system.Restart(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Agents may now update and force-push %s in %s while it points at %s.\n", args[2], repo, args[3][:7])
		return nil
	}
	return errors.New(ledgerUsage)
}
