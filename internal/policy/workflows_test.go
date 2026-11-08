package policy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type repo struct {
	t   *testing.T
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
	for _, line := range strings.Split(strings.TrimSpace(list), "\n") {
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
		got, err := WorkflowChanges(p, []RefUpdate{{Old: old, New: tip, Ref: "refs/heads/agent/x"}}, def, r.fetch)
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
}

func TestParseCommitReadsLikeGit(t *testing.T) {
	const a = "1111111111111111111111111111111111111111"
	const b = "2222222222222222222222222222222222222222"
	good := "tree " + a + "\nparent " + b + "\nauthor x <x> 1 +0000\ncommitter x <x> 1 +0000\n\nmsg\n"
	if c, err := ParseCommit([]byte(good)); err != nil || c.Tree != a || len(c.Parents) != 1 {
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
