package sshgate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
)

func TestLedgerReplaysTips(t *testing.T) {
	const (
		a = "1111111111111111111111111111111111111111"
		b = "2222222222222222222222222222222222222222"
	)
	path := filepath.Join(t.TempDir(), "branches.jsonl")
	// A line from before tips were recorded names the branch but matches
	// no push.
	os.WriteFile(path, []byte(`{"repo":"acme/widgets","branch":"old","created":"2026-11-01T00:00:00Z"}`+"\n"), 0o600)
	repo := github.Repo{Owner: "acme", Name: "widgets"}
	l := OpenLedger(path)
	for _, step := range []struct{ branch, tip string }{
		{"fix", a}, {"fix", b}, {"gone", a}, {"gone", ""},
	} {
		if err := l.Record(repo, step.branch, step.tip, "test"); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range []*Ledger{l, OpenLedger(path)} {
		for branch, want := range map[string]string{"fix": b, "gone": "", "old": "", "never": ""} {
			if got := l.Tip(repo, branch); got != want {
				t.Errorf("Tip(%s) = %q, want %q", branch, got, want)
			}
		}
		if got := l.Branches(repo); len(got) != 2 || got["fix"] != b {
			t.Errorf("Branches = %v, want fix and old", got)
		}
	}
}

func TestLedgerRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	path := filepath.Join(dir, "branches.jsonl")
	os.Symlink(target, path)
	err := OpenLedger(path).Record(github.Repo{Owner: "acme", Name: "widgets"}, "fix", "1111111111111111111111111111111111111111", "test")
	if err == nil {
		t.Error("Record wrote through a symlink")
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("the symlink's target was created")
	}
}
