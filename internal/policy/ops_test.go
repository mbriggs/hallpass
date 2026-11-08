package policy

import (
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
)

// Every write names a known operation, so none slips through CheckOps with
// an empty list, and every operation is something a request can need, so no
// name in the config does nothing.
func TestEveryWriteHasAnOperation(t *testing.T) {
	used := map[op.Op]bool{}
	known := func(where string, o op.Op) {
		t.Helper()
		if _, ok := op.Lookup(string(o)); !ok {
			t.Errorf("%s names %q, which op.All doesn't list", where, o)
		}
		used[o] = true
	}

	for _, w := range restWrites(github.Repo{Owner: "acme", Name: "widgets"}, nil) {
		where := "REST " + w.method + " " + w.path
		if w.op == "" {
			t.Errorf("%s has no operation", where)
			continue
		}
		known(where, w.op)
		for k, o := range w.opKeys {
			known(where+" key "+k, o)
		}
	}
	for name, m := range mutations {
		if m.op == "" {
			t.Errorf("mutation %s has no operation", name)
		} else {
			known("mutation "+name, m.op)
		}
		for k, o := range m.opFields {
			known("mutation "+name+" field "+k, o)
		}
	}
	for _, event := range []string{"APPROVE", "REQUEST_CHANGES"} {
		o, err := verdict(event)
		if err != nil {
			t.Fatal(err)
		}
		known("review event "+event, o)
	}
	// A push to the default branch needs push.default, and its refusal says
	// how to allow it, like every other operation's.
	main := RefUpdate{Old: zeroOID, New: strings.Repeat("a", 40), Ref: "refs/heads/main"}
	br := Branches{Default: "main", Ops: op.Defaults(), Repo: github.Repo{Owner: "acme", Name: "widgets"}}
	if why := CheckPush(Push{Updates: []RefUpdate{main}}, br)[main.Ref]; strings.Contains(why, "policy allow push.default --repo acme/widgets") {
		used[op.PushDefault] = true
	} else {
		t.Errorf("default branch refusal doesn't name push.default: %q", why)
	}

	for _, info := range op.All {
		if !used[info.Op] {
			t.Errorf("no request needs %s, so allowing or denying it does nothing", info.Op)
		}
	}
}

// A mutation entry with no operation is refused at the node check, not
// waved through.
func TestWriteWithoutOperationIsRefused(t *testing.T) {
	use := NodeUse{ID: "X", Types: []string{"Issue"}, Write: true, Where: "untagged.id"}
	n := Node{Type: "Issue", Repo: github.Repo{Owner: "acme", Name: "widgets"}, Authored: true}
	allowed := func(github.Repo) (bool, op.Set, bool) { return true, op.Defaults(), true }
	if err := CheckNode(use, n, allowed); err == nil {
		t.Error("a write with no operation passed CheckNode")
	}
	if err := CheckOps([]op.Op{"nope"}, op.Set{"nope": true}, n.Repo); err == nil {
		t.Error("CheckOps passed an operation op.All doesn't list")
	}
}
