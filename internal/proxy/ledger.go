package proxy

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mbriggs/hallpass/internal/github"
)

// Ledger records the branches this machine's agents created, so they may
// later update, force-push, or delete those and no others. It's an
// append-only file in the state dir. Entries are written only after GitHub
// confirms the create.
type Ledger struct {
	path string
	mu   sync.Mutex
	set  map[string]bool
}

type ledgerEntry struct {
	Repo    string    `json:"repo"`
	Branch  string    `json:"branch"`
	Created time.Time `json:"created"`
	Procs   string    `json:"procs,omitempty"`
}

func ledgerKey(repo github.Repo, branch string) string {
	return repo.Key() + "\x00" + branch
}

// OpenLedger reads the ledger at path. A missing or corrupt file starts
// empty, which only means agents can't update branches they made before.
func OpenLedger(path string) *Ledger {
	l := &Ledger{path: path, set: map[string]bool{}}
	f, err := os.Open(path)
	if err != nil {
		return l
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e ledgerEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if r, err := github.ParseRepo(e.Repo); err == nil {
			l.set[ledgerKey(r, e.Branch)] = true
		}
	}
	return l
}

// Has reports whether agents created branch in repo.
func (l *Ledger) Has(repo github.Repo, branch string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.set[ledgerKey(repo, branch)]
}

// Add records branch. It returns an error when the entry couldn't be saved;
// the broker logs it, and agents then can't update that branch.
func (l *Ledger) Add(repo github.Repo, branch, procs string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.set[ledgerKey(repo, branch)] {
		return nil
	}
	l.set[ledgerKey(repo, branch)] = true
	if l.path == "" {
		return nil
	}
	b, _ := json.Marshal(ledgerEntry{Repo: repo.String(), Branch: branch, Created: time.Now().UTC(), Procs: procs})
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// Branches lists the ledger's branches for repo.
func (l *Ledger) Branches(repo github.Repo) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	prefix := repo.Key() + "\x00"
	for k := range l.set {
		if b, ok := strings.CutPrefix(k, prefix); ok {
			out = append(out, b)
		}
	}
	return out
}
