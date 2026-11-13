package policy

// Over HTTPS, GitHub refuses a push that changes .github/workflows from a
// token without workflow scope. Over SSH it doesn't, so the broker checks
// what a push would make the ref run.
//
// GitHub runs a push's workflows from the commit the ref ends up at, so the
// check is on that commit, wherever it came from: the pack, or a commit
// already on GitHub, such as a fork PR's head. Its .github/workflows entry
// must match one GitHub already trusts for that ref: the ref's old commit,
// or the default branch's head, which covers merging or rebasing onto main
// after someone else changed workflows there. Only the entry's ID is
// compared, so blob contents are never needed.
//
// Dependabot's config gets the same check. Dependabot reads it from the
// default branch, and a registry it names receives the Dependabot secrets
// the config references, so an agent allowed push.default could send them
// to a server of its own.
//
// The config's protected_paths add paths to the same check, like the
// scripts a workflow runs with secrets, or composite actions. A path is a
// file or a directory, compared by its entry's mode and ID, so a directory
// covers everything under it.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
)

// Guarded are the paths a push may not change in any repo. No config or
// policy removes them.
var Guarded = []string{".github/workflows", ".github/dependabot.yml", ".github/dependabot.yaml"}

// maxWant bounds the commits the check asks GitHub for. A push names
// that many only by building on that many commits outside its pack, and
// each costs memory here and a line in the fetch.
const maxWant = 1 << 16

// Fetch returns the commits and trees of the given commits already on
// GitHub, without blobs.
type Fetch func(commits []string) (map[string]Object, error)

// WorkflowChanges returns, per ref, why the push can't go through: its new
// commit changes workflows or a protected path, or the broker couldn't
// tell. defaultHead is the default branch's commit, or "" for an empty
// repo. protected are the config's paths, checked on top of Guarded.
func WorkflowChanges(p *Pack, updates []RefUpdate, defaultHead string, protected []string, fetch Fetch) (map[string]string, error) {
	// The pack's objects win over GitHub's, as they're what the push sends.
	var extra map[string]Object
	get := func(id string) (Object, bool) {
		if o, ok := p.Objects[id]; ok {
			return o, true
		}
		o, ok := extra[id]
		return o, ok
	}
	commitOf := func(id string) (Commit, bool, error) {
		o, ok := get(id)
		if !ok || o.Type != "commit" {
			return Commit{}, false, nil
		}
		c, err := ParseCommit(o.Data)
		return c, true, err
	}

	// Everything the comparison needs that isn't in the pack is on GitHub:
	// the baselines, a tip pushed without its objects, and the parents the
	// pack builds on, whose trees hold any subtree the push didn't change.
	want := map[string]bool{}
	need := func(id string) {
		if id != "" && id != zeroOID {
			if _, ok := p.Objects[id]; !ok {
				want[id] = true
			}
		}
	}
	need(defaultHead)
	for _, o := range p.Objects {
		if o.Type != "commit" {
			continue
		}
		c, err := ParseCommit(o.Data)
		if err != nil {
			return nil, err
		}
		for _, parent := range c.Parents {
			need(parent)
		}
	}
	for _, u := range updates {
		if !u.Delete() {
			need(u.New)
			need(u.Old)
		}
	}
	if len(want) > maxWant {
		return nil, errorf("this push builds on too many commits for hallpass to check")
	}
	if len(want) > 0 {
		var ids []string
		for id := range want {
			ids = append(ids, id)
		}
		var err error
		if extra, err = fetch(ids); err != nil {
			return nil, err
		}
	}

	paths := append(slices.Clone(Guarded), protected...)
	// states returns what each path holds at commit, or why it can't
	// say: an object it needs is in neither the pack nor GitHub's answer,
	// or a tree on the way is one the walk refuses.
	states := func(commit string) ([]string, string) {
		out := make([]string, len(paths))
		if commit == "" || commit == zeroOID {
			return out, ""
		}
		c, ok, err := commitOf(commit)
		if err != nil || !ok {
			return nil, unknown
		}
		for i, path := range paths {
			var why string
			if out[i], why = pathState(get, c.Tree, path); why != "" {
				return nil, why
			}
		}
		return out, ""
	}

	refused := map[string]string{}
	base, baseWhy := states(defaultHead)
	for _, u := range updates {
		if u.Delete() {
			continue
		}
		tip, why := states(u.New)
		if why == "" {
			why = baseWhy
		}
		if why != "" {
			refused[u.Ref] = why
			continue
		}
		// The tip must match one baseline at every path at once, as a
		// mix of the two is something neither baseline ran.
		trusted := slices.Equal(tip, base)
		var old []string
		if !u.Create() {
			if old, why = states(u.Old); why != "" {
				refused[u.Ref] = why
				continue
			}
			trusted = trusted || slices.Equal(tip, old)
		}
		if !trusted {
			refused[u.Ref] = changedPaths(paths, tip, base, old)
		}
	}
	return refused, nil
}

// changedPaths says which paths the tip changed: those that match neither
// baseline, or when each matches one but not the same one, those that
// differ from the default branch.
func changedPaths(paths, tip, base, old []string) string {
	var changed []string
	for i := range paths {
		if tip[i] != base[i] && (old == nil || tip[i] != old[i]) {
			changed = append(changed, paths[i])
		}
	}
	if len(changed) == 0 {
		for i := range paths {
			if tip[i] != base[i] {
				changed = append(changed, paths[i])
			}
		}
	}
	for _, p := range changed {
		if slices.Contains(Guarded, p) {
			return "agents can't change .github/workflows or Dependabot's config. Push that change yourself with git personal push"
		}
	}
	return "agents can't change " + strings.Join(slices.Compact(changed), ", ") + ", which protected_paths in hallpass's config names. Push that change yourself with git personal push"
}

// pathState describes what path holds under the tree root: each entry on
// the way whose name matches the path's, case-insensitively, since a
// checkout on macOS or Windows reads Scripts/ as scripts/. An entry that
// should be a directory and isn't, like a symlink or a submodule, ends the
// walk and goes in the state, so replacing a directory with one is a
// change. An absent path is "". The second result says why the walk
// failed, or is "": a tree it needs is missing, more than maxMatches
// entries match, since a crafted tree that repeats a name would otherwise
// multiply the walk at every level, or a tree holds a name foldEntries
// refuses.
func pathState(get func(string) (Object, bool), root, path string) (string, string) {
	type at struct{ id, path string }
	cur := []at{{root, ""}}
	segs := strings.Split(path, "/")
	var state strings.Builder
	left := maxMatches
	for i, seg := range segs {
		var next []at
		for _, d := range cur {
			t, ok := get(d.id)
			if !ok || t.Type != "tree" {
				return "", unknown
			}
			entries, err := foldEntries(t.Data, seg, left)
			if errors.Is(err, errSlashName) {
				return "", err.Error()
			}
			if err != nil {
				return "", unknown
			}
			left -= len(entries)
			for _, e := range entries {
				name := d.path + e.name
				if i < len(segs)-1 && e.mode == "40000" {
					next = append(next, at{e.id, name + "/"})
					continue
				}
				state.WriteString(name + "=" + e.mode + " " + e.id + ";")
			}
		}
		cur = next
	}
	return state.String(), ""
}

const unknown = "hallpass couldn't check this push for workflow changes"

// errSlashName refuses a tree with a slash in an entry's name. The walk
// matches one path segment to one entry, so a root entry named
// scripts/deploy.sh matches nothing, yet git checks it out as the file
// deploy.sh in scripts. git never writes such a tree and its fsck rejects
// one, but the broker's check is the only guard the README promises, so it
// doesn't count on GitHub running fsck.
var errSlashName = errorf("a tree in this push has an entry with a / in its name, which git doesn't write")

type treeEntry struct{ mode, name, id string }

// maxMatches bounds the entries one path's walk may match. A real tree has
// one entry per name, and maybe a second that differs in case.
const maxMatches = 64

// foldEntries returns the entries of a tree whose names match name,
// ignoring case. It fails past limit matches.
func foldEntries(data []byte, name string, limit int) ([]treeEntry, error) {
	var out []treeEntry
	want := []byte(name)
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		nul := bytes.IndexByte(data, 0)
		if sp < 0 || nul < sp || nul+21 > len(data) {
			return nil, errorf("malformed tree")
		}
		n := data[sp+1 : nul]
		if bytes.IndexByte(n, '/') >= 0 {
			return nil, errSlashName
		}
		if bytes.EqualFold(n, want) {
			if len(out) == limit {
				return nil, errorf("a tree in this push repeats a name")
			}
			out = append(out, treeEntry{string(data[:sp]), string(n), hex.EncodeToString(data[nul+1 : nul+21])})
		}
		data = data[nul+21:]
	}
	return out, nil
}
