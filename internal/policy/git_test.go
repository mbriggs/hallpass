package policy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestParseGit(t *testing.T) {
	const up = "application/x-git-upload-pack-request"
	const rp = "application/x-git-receive-pack-request"
	ok := []struct {
		method, target, ct string
		want               string
		svc                GitService
	}{
		{"GET", "/acme/widgets/info/refs?service=git-upload-pack", "", "acme/widgets", GitInfoRefsUpload},
		{"GET", "/acme/widgets.git/info/refs?service=git-receive-pack", "", "acme/widgets", GitInfoRefsReceive},
		{"POST", "/acme/widgets.git/git-upload-pack", up, "acme/widgets", GitUploadPack},
		{"POST", "/acme/widgets/git-receive-pack", rp, "acme/widgets", GitReceivePack},
	}
	for _, c := range ok {
		g, err := ParseGit(c.method, c.target, c.ct)
		if err != nil || g.Repo.String() != c.want || g.Service != c.svc {
			t.Errorf("ParseGit(%s %s) = %v, %v", c.method, c.target, g, err)
		}
	}
	bad := []struct{ method, target, ct string }{
		{"GET", "/acme/widgets/info/refs", ""},
		{"GET", "/acme/widgets/info/lfs/objects/batch", ""},
		{"GET", "/acme/../secret/info/refs?service=git-upload-pack", ""},
		{"GET", "/acme/%2e%2e/info/refs?service=git-upload-pack", ""},
		{"GET", "//acme/widgets/info/refs?service=git-upload-pack", ""},
		{"POST", "/acme/widgets/git-receive-pack", up},
		{"POST", "/acme/widgets/git-upload-pack?x=1", up},
		{"GET", "/acme/widgets/archive/main.zip", ""},
		{"GET", "http://evil/acme/widgets/info/refs?service=git-upload-pack", ""},
	}
	for _, c := range bad {
		if g, err := ParseGit(c.method, c.target, c.ct); err == nil {
			t.Errorf("ParseGit(%s %s) = %v, want refusal", c.method, c.target, g)
		}
	}
}

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
	ours := func(b string) bool { return b == "agent/mine" }
	br := Branches{Default: "main", Protected: []string{"release/*", "production"}, Ours: ours}
	cases := []struct {
		u    RefUpdate
		want bool // allowed
	}{
		{RefUpdate{zeroOID, a, "refs/heads/agent/new"}, true},
		{RefUpdate{a, b, "refs/heads/agent/mine"}, true},
		{RefUpdate{a, zeroOID, "refs/heads/agent/mine"}, true},
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

	// The default branch passes even when a protected pattern names it.
	br.PushDefault = true
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
