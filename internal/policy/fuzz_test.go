package policy

import (
	"bytes"
	"crypto/sha1"
	"os/exec"
	"strings"
	"testing"
)

// The workflow check is the only guard against agents changing
// .github/workflows over git, so these targets check what it relies on,
// not just that it doesn't crash. Run them with make fuzz.

// withTrailer appends the SHA-1 trailer a pack ends with, so mutated bodies
// get past the checksum and the fuzzer reaches the entries and deltas.
func withTrailer(body []byte) []byte {
	sum := sha1.Sum(body)
	return append(bytes.Clone(body), sum[:]...)
}

// fuzzRepo builds a repo whose history has deltas of both kinds and a
// workflow edit. It returns the repo, the base commit, a commit that changes
// only code, and one that changes a workflow.
func fuzzRepo(t testing.TB) (r repo, base, code, evil string) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	r = repo{t, t.TempDir()}
	r.git("", "init", "-q", "-b", "main")
	// A large file edited twice gives pack-objects something to delta.
	big := strings.Repeat("line of code\n", 400)
	r.write("src/main.go", big)
	r.write(".github/workflows/ci.yml", "on: push\njobs: {test: {}}\n")
	base = r.commit("base")
	r.write("src/main.go", big+"more\n")
	code = r.commit("code")
	r.write(".github/workflows/ci.yml", "on: push\njobs: {test: {}, steal: {}}\n")
	r.write("src/main.go", big+"more\neven more\n")
	evil = r.commit("workflow edit")
	return r, base, code, evil
}

// seedPacks are real packs of the pushes, without their trailers, with
// offset deltas and with ref deltas.
func seedPacks(r repo, tip, base string) [][]byte {
	var out [][]byte
	for _, flags := range [][]string{{"--delta-base-offset"}, {}} {
		args := append([]string{"pack-objects", "--stdout", "--revs"}, flags...)
		raw := r.git(tip+"\n^"+base+"\n", args...)
		out = append(out, []byte(raw[:len(raw)-sha1.Size]))
	}
	return out
}

// Every object ReadPack keeps is stored under the hash of its own type and
// content. That's why a pack can't substitute a tree for one GitHub has.
func FuzzReadPack(f *testing.F) {
	r, base, code, evil := fuzzRepo(f)
	for _, tip := range []string{code, evil} {
		for _, p := range seedPacks(r, tip, base) {
			f.Add(p)
		}
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		p, err := ReadPack(bytes.NewReader(withTrailer(body)))
		if err != nil {
			return
		}
		for id, o := range p.Objects {
			if o.Type != "commit" && o.Type != "tree" {
				t.Fatalf("kept a %s object", o.Type)
			}
			if got := objectID(o.Type, o.Data); got != id {
				t.Fatalf("object stored as %s hashes to %s", id, got)
			}
		}
	})
}

// Whatever pack an agent sends, a push whose tip changes a workflow is
// refused. git itself is the oracle: the tip's .github/workflows differs
// from the base's.
func FuzzWorkflowChanges(f *testing.F) {
	r, base, _, evil := fuzzRepo(f)
	if r.git("", "rev-parse", evil+":.github/workflows") == r.git("", "rev-parse", base+":.github/workflows") {
		f.Fatal("the evil commit doesn't change workflows")
	}
	// GitHub's side: every commit and tree in the repo, fetched once.
	all, err := r.fetch([]string{base, evil, evil + "~1"})
	if err != nil {
		f.Fatal(err)
	}
	fetch := func(ids []string) (map[string]Object, error) {
		out := map[string]Object{}
		for _, id := range ids {
			if o, ok := all[id]; ok {
				out[id] = o
			}
		}
		return out, nil
	}
	for _, seed := range seedPacks(r, evil, base) {
		// Each seed parses, and the check refuses it, so the property
		// below isn't vacuous.
		p, err := ReadPack(bytes.NewReader(withTrailer(seed)))
		if err != nil {
			f.Fatalf("seed doesn't parse: %v", err)
		}
		u := RefUpdate{Old: zeroOID, New: evil, Ref: "refs/heads/agent/x"}
		if got, err := WorkflowChanges(p, []RefUpdate{u}, base, fetch); err != nil || got[u.Ref] == "" {
			f.Fatalf("seed push isn't refused: %v %v", got, err)
		}
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		p, err := ReadPack(bytes.NewReader(withTrailer(body)))
		if err != nil {
			return // refused before the check
		}
		for _, old := range []string{zeroOID, base} {
			u := RefUpdate{Old: old, New: evil, Ref: "refs/heads/agent/x"}
			refused, err := WorkflowChanges(p, []RefUpdate{u}, base, fetch)
			if err != nil {
				continue // the gate refuses the push on an error
			}
			if refused[u.Ref] == "" {
				t.Fatalf("a push of a workflow edit from %s went through", old[:7])
			}
		}
	})
}

// applyDelta runs on attacker-controlled bytes behind zlib, which the pack
// target rarely gets through, so it gets its own target. The gate has no
// recover, so a panic here would stop the broker. A delta that applies
// yields exactly the size it declares.
func FuzzApplyDelta(f *testing.F) {
	base := []byte("hello, world")
	// Source size 12, target size 5, copy 5 bytes from offset 0.
	f.Add(base, []byte{12, 5, 0x80 | 0x01 | 0x10, 0, 5})
	// Source size 12, target size 3, insert "abc".
	f.Add(base, []byte{12, 3, 3, 'a', 'b', 'c'})
	// Copy with the 0x10000 default size against a short base.
	f.Add(base, []byte{12, 0x80, 0x80, 0x04, 0x80})
	f.Fuzz(func(t *testing.T, base, delta []byte) {
		out, err := applyDelta(base, delta)
		if err != nil {
			return
		}
		// The second varint in the delta is the target size.
		d := delta
		for d[0]&0x80 != 0 {
			d = d[1:]
		}
		d = d[1:]
		var size uint64
		for i := uint(0); ; i += 7 {
			size |= uint64(d[0]&0x7f) << i
			if d[0]&0x80 == 0 {
				break
			}
			d = d[1:]
		}
		if uint64(len(out)) != size {
			t.Fatalf("delta declares %d bytes, produced %d", size, len(out))
		}
	})
}
