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

// guarded are the entries of .github a push may not change.
var guarded = []string{"workflows", "dependabot.yml", "dependabot.yaml"}

// maxWant bounds the commits the check asks GitHub for. A push names
// that many only by building on that many commits outside its pack, and
// each costs memory here and a line in the fetch.
const maxWant = 1 << 16

// Fetch returns the commits and trees of the given commits already on
// GitHub, without blobs.
type Fetch func(commits []string) (map[string]Object, error)

// WorkflowChanges returns, per ref, why the push can't go through: its new
// commit changes workflows, or the broker couldn't tell. defaultHead is the
// default branch's commit, or "" for an empty repo.
func WorkflowChanges(p *Pack, updates []RefUpdate, defaultHead string, fetch Fetch) (map[string]string, error) {
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

	entry := func(commit string) (string, bool) {
		if commit == "" || commit == zeroOID {
			return "", true
		}
		c, ok, err := commitOf(commit)
		if err != nil || !ok {
			return "", false
		}
		t, ok := get(c.Tree)
		if !ok || t.Type != "tree" {
			return "", false
		}
		mode, id, err := TreeEntry(t.Data, ".github")
		if err != nil {
			return "", false
		}
		if id == "" {
			return "", true
		}
		if mode != "40000" {
			return mode + " " + id, true
		}
		gh, ok := get(id)
		if !ok || gh.Type != "tree" {
			return "", false
		}
		var key string
		for _, name := range guarded {
			mode, id, err := TreeEntry(gh.Data, name)
			if err != nil {
				return "", false
			}
			// Absent entries add nothing, so a .github with none of them
			// matches no .github at all.
			if id != "" {
				key += name + "=" + mode + " " + id + ";"
			}
		}
		return key, true
	}

	const unknown = "hallpass couldn't check this push for workflow changes"
	refused := map[string]string{}
	base, baseOK := entry(defaultHead)
	for _, u := range updates {
		if u.Delete() {
			continue
		}
		tip, ok := entry(u.New)
		if !ok || !baseOK {
			refused[u.Ref] = unknown
			continue
		}
		trusted := tip == base
		if !u.Create() {
			old, ok := entry(u.Old)
			if !ok {
				refused[u.Ref] = unknown
				continue
			}
			trusted = trusted || tip == old
		}
		if !trusted {
			refused[u.Ref] = "agents can't change .github/workflows or Dependabot's config. Push that change yourself with git personal push"
		}
	}
	return refused, nil
}
