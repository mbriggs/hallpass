package sshgate

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mbriggs/hallpass/internal/github"
)

// Ledger records, for each branch this machine's agents created, the commit
// an agent last pushed to it. Agents may update, force-push, or delete such a
// branch only while it still points at that commit. GitHub applies a ref
// update only if the ref still has the old commit the push names, so a branch
// the user deleted and made again, or pushed to, no longer matches and is
// the user's again.
//
// It's an append-only file in the state dir, one line per change, where the
// last line for a branch wins. Lines are written only after GitHub confirms
// the push.
type Ledger struct {
	path string
	mu   sync.Mutex
	tips map[string]string
}

type ledgerEntry struct {
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
	// Tip is the commit agents may update from. Lines written before tips
	// were recorded have none, and match no push.
	Tip     string    `json:"tip,omitempty"`
	Deleted bool      `json:"deleted,omitempty"`
	Time    time.Time `json:"time"`
	Procs   string    `json:"procs,omitempty"`
}

func ledgerKey(repo github.Repo, branch string) string {
	return repo.Key() + "\x00" + branch
}

// OpenLedger reads the ledger at path. A missing or corrupt file starts
// empty, which only means agents can't update branches they made before.
func OpenLedger(path string) *Ledger {
	l := &Ledger{path: path, tips: map[string]string{}}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
		r, err := github.ParseRepo(e.Repo)
		if err != nil {
			continue
		}
		if e.Deleted {
			delete(l.tips, ledgerKey(r, e.Branch))
		} else {
			l.tips[ledgerKey(r, e.Branch)] = e.Tip
		}
	}
	return l
}

// Tip returns the commit agents may update branch from, or "" when agents
// may not update it.
func (l *Ledger) Tip(repo github.Repo, branch string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tips[ledgerKey(repo, branch)]
}

// Record sets the commit agents may update branch from. An empty tip
// removes the branch, after agents delete it. Record returns an error when
// the line couldn't be saved; the broker logs it, and after a restart the
// ledger has the branch's previous tip, which then matches no push.
func (l *Ledger) Record(repo github.Repo, branch, tip, procs string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := ledgerKey(repo, branch)
	if old, ok := l.tips[key]; ok && old == tip || !ok && tip == "" {
		return nil
	}
	e := ledgerEntry{Repo: repo.String(), Branch: branch, Tip: tip, Time: time.Now().UTC(), Procs: procs}
	if tip == "" {
		delete(l.tips, key)
		e.Deleted = true
	} else {
		l.tips[key] = tip
	}
	if l.path == "" {
		return nil
	}
	b, _ := json.Marshal(e)
	// ledger add writes as root into the broker user's state dir, so a
	// symlink planted there must not redirect the write.
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// Branches maps each of the ledger's branches for repo to its tip.
func (l *Ledger) Branches(repo github.Repo) map[string]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]string{}
	prefix := repo.Key() + "\x00"
	for k, tip := range l.tips {
		if b, ok := strings.CutPrefix(k, prefix); ok {
			out[b] = tip
		}
	}
	return out
}
