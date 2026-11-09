package policy

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
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
func fuzzRepo(tb testing.TB) (r repo, base, code, evil string) {
	tb.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		tb.Skip("no git")
	}
	r = repo{tb, tb.TempDir()}
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

// The broker checks the commands ReadPush parsed, then sends GitHub p.Raw
// and the rest of the body. So Raw must parse back to exactly the commands
// that were checked, and the pack must start right where ReadPush stopped.
func FuzzReadPush(f *testing.F) {
	for _, lines := range [][]string{
		{zeroOID + " " + a + " refs/heads/agent/x\x00report-status side-band-64k agent=git/2.56\n", a + " " + b + " refs/heads/agent/y\n"},
		{a + " " + zeroOID + " refs/heads/agent/x\x00report-status-v2 delete-refs atomic quiet\n"},
		{a + " " + b + " refs/tags/v1\x00ofs-delta object-format=sha1 session-id=abc\n"},
	} {
		var s strings.Builder
		for _, l := range lines {
			s.WriteString(pkt(l))
		}
		s.WriteString("0000PACK")
		f.Add([]byte(s.String()))
	}
	f.Add([]byte("0000"))
	f.Fuzz(func(t *testing.T, body []byte) {
		r := bufio.NewReader(bytes.NewReader(body))
		p, err := ReadPush(r)
		if err != nil {
			return
		}
		rest, _ := io.ReadAll(r)
		if p.Read > len(body) || !bytes.Equal(rest, body[p.Read:]) {
			t.Fatalf("Read = %d, but %d bytes are left of %d", p.Read, len(rest), len(body))
		}
		again, err := ReadPush(bufio.NewReader(bytes.NewReader(p.Raw)))
		if err != nil {
			t.Fatalf("Raw %q doesn't parse: %v", p.Raw, err)
		}
		if !slices.Equal(again.Updates, p.Updates) || !slices.Equal(again.Capabilities, p.Capabilities) ||
			again.Probe != p.Probe || !bytes.Equal(again.Raw, p.Raw) || again.Read != len(p.Raw) {
			t.Fatalf("checked %+v, but sent %q, which parses as %+v", p, p.Raw, again)
		}
	})
}

// The broker checks its own parse of a GraphQL request and sends GitHub
// that parse printed back out. The printed request must classify exactly as
// the checked one did, or the check and what GitHub runs disagree.
func FuzzGraphQLReprint(f *testing.F) {
	for _, body := range captureGraphQL(f) {
		var req struct {
			Query     string          `json:"query"`
			Variables json.RawMessage `json:"variables"`
		}
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			f.Fatal(err)
		}
		f.Add(req.Query, string(req.Variables))
	}
	for _, q := range []string{
		`{repository(owner:"acme",name:"widgets"){issue(number:1){title body}}}`,
		`query($o:String!,$n:String!){r:repository(owner:$o,name:$n){...F}} fragment F on Repository{name}`,
		`{nodes(ids:["PR_a","I_b"]){id ... on PullRequest{title}}}`,
		`{search(query:"repo:acme/widgets is:open label:bug",type:ISSUE,first:5){issueCount}}`,
		`mutation{addComment(input:{subjectId:"X",body:"say \"hi\"\\n\u00e9"}){clientMutationId}}`,
		`{viewer{login}}`,
		`mutation{addComment(input:{subjectId:"X",body:"""block\nstring"""}){clientMutationId}}`,
		`mutation($i:AddLabelsToLabelableInput!){addLabelsToLabelable(input:$i){clientMutationId}}`,
	} {
		vars := `{"o":"acme","n":"widgets","i":{"labelableId":"X","labelIds":["L"]}}`
		// Each seed is allowed, so the fuzzer starts past the checks.
		if _, err := ClassifyGraphQL(fuzzGQL(q, vars), nil); err != nil {
			f.Fatalf("seed %s is refused: %v", q, err)
		}
		f.Add(q, vars)
	}
	f.Fuzz(func(t *testing.T, query, vars string) {
		body := fuzzGQL(query, vars)
		g, err := ClassifyGraphQL(body, nil)
		if err != nil {
			return
		}
		again, err := ClassifyGraphQL(g.Body, nil)
		if err != nil {
			t.Fatalf("checked %s\nbut sent %s\nwhich is refused: %v", body, g.Body, err)
		}
		if again.Mutation != g.Mutation || !slices.Equal(again.Fields, g.Fields) ||
			!reflect.DeepEqual(again.Repos, g.Repos) || !reflect.DeepEqual(again.Nodes, g.Nodes) {
			t.Fatalf("checked %s as %+v\nbut sent %s, which is %+v", body, g, g.Body, again)
		}
		if !bytes.Equal(again.Body, g.Body) {
			t.Fatalf("printing isn't stable:\n%s\n%s", g.Body, again.Body)
		}
	})
}

// fuzzGQL builds a request body, leaving out vars unless it's valid JSON.
func fuzzGQL(query, vars string) []byte {
	req := map[string]any{"query": query}
	if json.Valid([]byte(vars)) {
		req["variables"] = json.RawMessage(vars)
	}
	body, _ := json.Marshal(req)
	return body
}

// captureGraphQL returns the GraphQL bodies gh sent in the recorded captures.
func captureGraphQL(tb testing.TB) []string {
	tb.Helper()
	files, _ := filepath.Glob("testdata/gh-*-capture.jsonl")
	var out []string
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			tb.Fatal(err)
		}
		for line := range bytes.Lines(data) {
			var rec struct{ Head, Body string }
			if err := json.Unmarshal(line, &rec); err != nil {
				tb.Fatal(err)
			}
			if strings.HasPrefix(rec.Head, "POST /graphql ") {
				out = append(out, strings.ReplaceAll(rec.Body, `"id":""`, `"id":"PR_x"`))
			}
		}
	}
	if len(out) == 0 {
		tb.Fatal("no GraphQL requests in testdata")
	}
	return out
}
