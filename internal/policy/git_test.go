package policy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
)

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

const (
	a = "1111111111111111111111111111111111111111"
	b = "2222222222222222222222222222222222222222"
)

func push(lines ...string) *bufio.Reader {
	var s strings.Builder
	for _, l := range lines {
		s.WriteString(pkt(l))
	}
	s.WriteString("0000PACKDATA")
	return bufio.NewReader(strings.NewReader(s.String()))
}

func TestReadPush(t *testing.T) {
	r := push(zeroOID+" "+a+" refs/heads/agent/x\x00report-status side-band-64k agent=git/2.56\n",
		a+" "+b+" refs/heads/agent/y\n")
	p, err := ReadPush(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Updates) != 2 || !p.Updates[0].Create() || p.Updates[1].Branch() != "agent/y" || !p.SideBand() {
		t.Fatalf("got %+v", p)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "PACKDATA" {
		t.Errorf("pack left in reader = %q", rest)
	}
	// What the broker forwards parses back to the same commands.
	again, err := ReadPush(bufio.NewReader(bytes.NewReader(p.Raw)))
	if err != nil || fmt.Sprint(again.Updates) != fmt.Sprint(p.Updates) {
		t.Errorf("re-encoded push = %+v, %v", again, err)
	}

	probe, err := ReadPush(bufio.NewReader(strings.NewReader("0000")))
	if err != nil || !probe.Probe {
		t.Errorf("probe = %+v, %v", probe, err)
	}
}

func TestReadPushRefuses(t *testing.T) {
	cases := map[string]*bufio.Reader{
		"push-cert":    push("push-cert\x00report-status\n"),
		"push options": push(zeroOID + " " + a + " refs/heads/x\x00report-status push-options\n"),
		"unknown cap":  push(zeroOID + " " + a + " refs/heads/x\x00report-status fancy\n"),
		"no caps":      push(zeroOID + " " + a + " refs/heads/x\n"),
		"short oid":    push("abc " + a + " refs/heads/x\x00report-status\n"),
		"shallow":      push(zeroOID+" "+a+" refs/heads/x\x00report-status\n", "shallow "+a+"\n"),
		"bad length":   bufio.NewReader(strings.NewReader("zzzz")),
		"tiny length":  bufio.NewReader(strings.NewReader("0002")),
		"truncated":    bufio.NewReader(strings.NewReader("00ff" + zeroOID)),
		"oversized":    bufio.NewReader(strings.NewReader(strings.Repeat(pkt(zeroOID+" "+a+" refs/heads/"+strings.Repeat("x", 60000)), 2))),
	}
	for name, r := range cases {
		if _, err := ReadPush(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckPush(t *testing.T) {
	// Agents last pushed a to agent/mine.
	tip := func(br string) string {
		if br == "agent/mine" {
			return a
		}
		return ""
	}
	br := Branches{Default: "main", Protected: []string{"release/*", "production"}, Tip: tip, Repo: github.Repo{Owner: "acme", Name: "widgets"}, Ops: op.Defaults()}
	cases := []struct {
		u    RefUpdate
		want bool // allowed
	}{
		{RefUpdate{zeroOID, a, "refs/heads/agent/new"}, true},
		{RefUpdate{a, b, "refs/heads/agent/mine"}, true},
		{RefUpdate{a, zeroOID, "refs/heads/agent/mine"}, true},
		// agent/mine moved to b since an agent pushed it: the user's now.
		{RefUpdate{b, a, "refs/heads/agent/mine"}, false},
		{RefUpdate{b, zeroOID, "refs/heads/agent/mine"}, false},
		{RefUpdate{a, b, "refs/heads/colleague"}, false},
		{RefUpdate{a, zeroOID, "refs/heads/colleague"}, false},
		{RefUpdate{zeroOID, a, "refs/heads/main"}, false},
		{RefUpdate{a, b, "refs/heads/Main"}, false},
		{RefUpdate{zeroOID, a, "refs/heads/release/1.0"}, false},
		{RefUpdate{zeroOID, a, "refs/heads/production"}, false},
		{RefUpdate{zeroOID, a, "refs/tags/v1"}, false},
		{RefUpdate{zeroOID, a, "refs/pull/1/head"}, false},
		{RefUpdate{zeroOID, a, "refs/heads/../main"}, false},
		{RefUpdate{zeroOID, a, "refs/heads/x.lock"}, false},
		{RefUpdate{zeroOID, a, "HEAD"}, false},
	}
	for _, c := range cases {
		got := CheckPush(Push{Updates: []RefUpdate{c.u}}, br)
		if (len(got) == 0) != c.want {
			t.Errorf("%s %s: refused=%v, want allowed=%v", c.u.Ref, c.u.New[:4], got, c.want)
		}
	}

	// A changed branch's refusal says how to hand it over as it is.
	got := CheckPush(Push{Updates: []RefUpdate{{b, a, "refs/heads/agent/mine"}}}, br)
	if want := "ledger add acme/widgets agent/mine " + b; !strings.Contains(got["refs/heads/agent/mine"], want) {
		t.Errorf("refusal %q doesn't say %q", got["refs/heads/agent/mine"], want)
	}
	// One ref twice in a push is refused, since the ledger reads GitHub's
	// answer by ref.
	twice := Push{Updates: []RefUpdate{{zeroOID, a, "refs/heads/agent/new"}, {zeroOID, b, "refs/heads/agent/new"}}}
	if got := CheckPush(twice, br); len(got) == 0 {
		t.Error("a push naming one ref twice was allowed")
	}

	// The default branch passes even when a protected pattern names it.
	br.Ops = op.Set{op.PushDefault: true}
	br.Protected = append(br.Protected, "main")
	for _, c := range []struct {
		u    RefUpdate
		want bool
	}{
		{RefUpdate{a, b, "refs/heads/main"}, true},
		{RefUpdate{a, b, "refs/heads/Main"}, true},
		{RefUpdate{zeroOID, a, "refs/heads/main"}, true},
		{RefUpdate{a, zeroOID, "refs/heads/main"}, false},
		{RefUpdate{a, b, "refs/heads/colleague"}, false},
		{RefUpdate{zeroOID, a, "refs/heads/production"}, false},
		{RefUpdate{zeroOID, a, "refs/tags/v1"}, false},
	} {
		got := CheckPush(Push{Updates: []RefUpdate{c.u}}, br)
		if (len(got) == 0) != c.want {
			t.Errorf("push.default %s %s: refused=%v, want allowed=%v", c.u.Ref, c.u.New[:4], got, c.want)
		}
	}
}

func TestRefusePushIsReadableStatus(t *testing.T) {
	p := Push{
		Updates:      []RefUpdate{{a, b, "refs/heads/main"}, {zeroOID, a, "refs/heads/ok"}},
		Capabilities: []string{"report-status", "side-band-64k"},
	}
	out := RefusePush(p, map[string]string{"refs/heads/main": "main is the default branch"})
	if !bytes.Contains(out, []byte("ng refs/heads/main hallpass: main is the default branch")) ||
		!bytes.Contains(out, []byte("ng refs/heads/ok hallpass: another ref")) {
		t.Errorf("refusal = %q", out)
	}
	// GitHub's own success report, side-band framed, yields the accepted refs.
	var status bytes.Buffer
	writePkt(&status, "unpack ok\n")
	writePkt(&status, "ok refs/heads/agent/x\n")
	writePkt(&status, "ng refs/heads/agent/y non-fast-forward\n")
	status.WriteString("0000")
	var framed bytes.Buffer
	writePkt(&framed, "\x02remote: hello\n")
	writePkt(&framed, "\x01"+status.String())
	framed.WriteString("0000")
	if got := ReportStatus(framed.Bytes(), true); len(got) != 1 || got[0] != "refs/heads/agent/x" {
		t.Errorf("ReportStatus = %v", got)
	}
}

// In an empty repo, the first branch pushed becomes the default, so it
// needs push.default like any default-branch push.
func TestCheckPushEmptyRepo(t *testing.T) {
	create := RefUpdate{zeroOID, a, "refs/heads/feature"}
	br := Branches{Ops: op.Defaults(), Repo: github.Repo{Owner: "acme", Name: "new"}}
	why := CheckPush(Push{Updates: []RefUpdate{create}}, br)[create.Ref]
	if !strings.Contains(why, "acme/new is empty") || !strings.Contains(why, "policy allow push.default") {
		t.Errorf("first push to an empty repo: %q", why)
	}
	br.Ops = op.Set{op.PushDefault: true}
	if got := CheckPush(Push{Updates: []RefUpdate{create}}, br); len(got) != 0 {
		t.Errorf("with push.default: %v", got)
	}
	// An empty default branch never lets an update or delete skip the
	// ledger, even with push.default.
	for _, u := range []RefUpdate{{a, b, "refs/heads/colleague"}, {a, zeroOID, "refs/heads/colleague"}} {
		if got := CheckPush(Push{Updates: []RefUpdate{u}}, br); len(got) == 0 {
			t.Errorf("%s from %s with no default branch went through", u.Ref, u.Old[:4])
		}
	}
}
