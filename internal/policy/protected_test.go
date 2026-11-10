package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A tree that repeats a name thousands of times, under a parent that does
// the same, would make the walk visit every pair. It's refused as
// uncheckable instead, at little cost.
func TestPathStateRefusesRepeatedNames(t *testing.T) {
	objs := map[string]Object{}
	put := func(typ string, data []byte) string {
		id := objectID(typ, data)
		objs[id] = Object{Type: typ, Data: data}
		return id
	}
	var inner, outer [][3]string
	for range 2000 {
		inner = append(inner, [3]string{"40000", "workflows", strings.Repeat("a", 40)})
	}
	gh := put("tree", treeData(inner...))
	for range 2000 {
		outer = append(outer, [3]string{"40000", ".github", gh})
	}
	tip := put("commit", []byte("tree "+put("tree", treeData(outer...))+"\n\nmsg\n"))
	p := &Pack{Objects: objs}
	allocs := testing.AllocsPerRun(1, func() {
		got, err := WorkflowChanges(p, []RefUpdate{{Old: zeroOID, New: tip, Ref: "refs/heads/x"}}, "", nil, func([]string) (map[string]Object, error) { return nil, nil })
		if err != nil || !strings.Contains(got["refs/heads/x"], "couldn't check") {
			t.Errorf("refused %v, %v", got, err)
		}
	})
	if allocs > 10000 {
		t.Errorf("the walk made %.0f allocations", allocs)
	}
}

// Protected paths from the config get the workflow check's rule: the tip
// must match the ref's old commit or the default branch at each of them.
func TestProtectedPaths(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	r := repo{t, t.TempDir()}
	r.git("", "init", "-q", "-b", "main")
	r.write("README", "hi\n")
	r.write(".github/workflows/ci.yml", "on: push\n")
	r.write("scripts/deploy.sh", "deploy\n")
	r.write("scripts/lint.sh", "lint\n")
	r.write(".github/actions/setup/action.yml", "runs: {using: composite}\n")
	base := r.commit("base")
	protected := []string{"scripts/deploy.sh", ".github/actions", "CODEOWNERS"}
	z := zeroOID

	// check pushes tip as a new branch, with main at def, and wants a
	// refusal that contains want, or none for "".
	check := func(name, tip, def, want string) {
		t.Helper()
		got, err := WorkflowChanges(r.pack(tip, base), []RefUpdate{{Old: z, New: tip, Ref: "refs/heads/agent/x"}}, def, protected, r.fetch)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if g := got["refs/heads/agent/x"]; (want == "") != (g == "") || !strings.Contains(g, want) {
			t.Errorf("%s: refused with %q, want %q", name, g, want)
		}
	}
	// branch starts a branch from base for one case.
	n := 0
	branch := func() {
		n++
		r.git("", "checkout", "-q", "-f", "-b", "case"+string(rune('a'+n)), base)
	}

	branch()
	r.write("scripts/deploy.sh", "deploy && curl evil\n")
	check("protected file edit", r.commit("edit deploy"), base,
		"agents can't change scripts/deploy.sh, which protected_paths in hallpass's config names. Push that change yourself with git personal push")

	branch()
	r.write("scripts/lint.sh", "lint --fix\n")
	check("neighbor edit", r.commit("edit lint"), base, "")

	branch()
	r.write(".github/actions/setup/action.yml", "runs: {using: composite, steps: [{run: curl evil}]}\n")
	check("nested file in a protected directory", r.commit("edit action"), base, "change .github/actions,")

	branch()
	r.write(".github/actions/new/action.yml", "runs: {using: composite}\n")
	check("new file under a protected directory", r.commit("new action"), base, "change .github/actions,")

	branch()
	r.write("CODEOWNERS", "* @agent\n")
	check("protected path that didn't exist", r.commit("add CODEOWNERS"), base, "change CODEOWNERS,")

	// Through the index, since a macOS checkout can't hold both names.
	branch()
	blob := strings.TrimSpace(r.git("evil\n", "hash-object", "-w", "--stdin"))
	r.git("", "update-index", "--add", "--cacheinfo", "100644,"+blob+",Scripts/deploy.sh")
	r.git("", "commit", "-q", "-m", "case")
	check("case variant of a protected path", strings.TrimSpace(r.git("", "rev-parse", "HEAD")), base, "change scripts/deploy.sh,")

	// A protected path absent on main, reached through a new symlink or
	// submodule in its place, is a change too.
	protected = append(protected, "tools/run.sh", "vendor/lib")
	branch()
	link := strings.TrimSpace(r.git("scripts", "hash-object", "-w", "--stdin"))
	r.git("", "update-index", "--add", "--cacheinfo", "120000,"+link+",tools")
	r.git("", "commit", "-q", "-m", "symlink tools")
	check("new symlink where a protected path would be", strings.TrimSpace(r.git("", "rev-parse", "HEAD")), base, "change tools/run.sh,")
	branch()
	r.git("", "update-index", "--add", "--cacheinfo", "160000,"+base+",vendor")
	r.git("", "commit", "-q", "-m", "gitlink vendor")
	check("new submodule where a protected path would be", strings.TrimSpace(r.git("", "rev-parse", "HEAD")), base, "change vendor/lib,")

	branch()
	r.git("", "rm", "-q", "scripts/deploy.sh")
	r.write("scripts/deploy.sh/run", "evil\n")
	check("protected file made a directory", r.commit("file to dir"), base, "change scripts/deploy.sh,")

	branch()
	r.git("", "rm", "-q", "-r", "scripts")
	os.RemoveAll(filepath.Join(r.dir, "scripts"))
	r.write("elsewhere/deploy.sh", "evil\n")
	os.Symlink("elsewhere", filepath.Join(r.dir, "scripts"))
	check("parent made a symlink", r.commit("symlink"), base, "change scripts/deploy.sh,")

	branch()
	r.git("", "rm", "-q", "scripts/deploy.sh")
	os.Symlink("lint.sh", filepath.Join(r.dir, "scripts", "deploy.sh"))
	check("protected file made a symlink", r.commit("file symlink"), base, "change scripts/deploy.sh,")

	branch()
	r.git("", "rm", "-q", "-r", "scripts")
	r.git("", "update-index", "--add", "--cacheinfo", "160000,"+base+",scripts")
	r.git("", "commit", "-q", "-m", "gitlink")
	check("parent made a submodule", strings.TrimSpace(r.git("", "rev-parse", "HEAD")), base, "change scripts/deploy.sh,")

	// Someone else changes deploy.sh on main. An agent branch built on it
	// carries main's version, which main already runs.
	r.git("", "checkout", "-q", "-f", "main")
	r.write("scripts/deploy.sh", "deploy v2\n")
	main2 := r.commit("user edits deploy")
	r.git("", "checkout", "-q", "-b", "rebased", main2)
	r.write("README", "agent\n")
	rebased := r.commit("agent work on new main")
	check("rebase onto main's change", rebased, main2, "")
	check("same branch while main hasn't changed", rebased, base, "change scripts/deploy.sh,")

	// A workflow change with a protected path change gets the workflow
	// refusal, as before.
	branch()
	r.write("scripts/deploy.sh", "evil\n")
	r.write(".github/workflows/ci.yml", "on: push\njobs: {evil: {}}\n")
	check("workflow and protected path", r.commit("both"), base, "agents can't change .github/workflows")
}
