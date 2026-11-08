package main

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/proxy"
	"github.com/mbriggs/hallpass/internal/system"
)

const ledgerUsage = `usage:
  hallpass ledger list OWNER/REPO
  sudo hallpass ledger add OWNER/REPO BRANCH`

// ledger shows or extends the record of branches agents may update. Agents
// can update, force-push, or delete only branches they created; add lets
// them work on one you made.
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
		branches := proxy.OpenLedger(path).Branches(repo)
		slices.Sort(branches)
		for _, b := range branches {
			fmt.Println(b)
		}
		return nil
	case args[0] == "add" && len(args) == 3:
		if err := system.RequireRoot("ledger add"); err != nil {
			return err
		}
		if err := proxy.OpenLedger(path).Add(repo, args[2], "added by hand"); err != nil {
			return err
		}
		if err := ownByService(path); err != nil {
			return err
		}
		if err := system.Restart(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Agents may now update and force-push %s in %s.\n", args[2], repo)
		return nil
	}
	return errors.New(ledgerUsage)
}
