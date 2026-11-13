package sshgate

import (
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/policy"
)

func adv(lines ...string) []byte {
	var b strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&b, "%04x%s\n", len(l)+5, l)
	}
	b.WriteString("0000")
	return []byte(b.String())
}

// The default branch is "" only for a repo with no refs at all, so an
// advertisement that loses HEAD can't pass as an empty repo.
func TestHeadBranch(t *testing.T) {
	id := strings.Repeat("a", 40)
	zero := strings.Repeat("0", 40)
	cases := []struct {
		name    string
		adv     []byte
		want    string
		wantErr bool
	}{
		{"normal", adv(id+" HEAD\x00multi_ack symref=HEAD:refs/heads/main agent=git/2", id+" refs/heads/main"), "main", false},
		{"empty repo", adv(zero + " capabilities^{}\x00multi_ack agent=git/2"), "", false},
		{"branches, no HEAD", adv(id+" refs/heads/main\x00multi_ack agent=git/2", id+" refs/heads/colleague"), "", true},
		{"empty HEAD target", adv(id + " HEAD\x00symref=HEAD:refs/heads/ agent=git/2"), "", true},
	}
	for _, c := range cases {
		got, err := headBranch(c.adv)
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("%s: headBranch = %q, %v", c.name, got, err)
		}
	}
}

// noThin adds no-thin to the capabilities on the ref list's first line, and
// leaves alone a list it can't add it to or that has it already.
func TestNoThin(t *testing.T) {
	id := strings.Repeat("a", 40)
	cases := []struct {
		name    string
		in, out []byte
	}{
		{"adds", adv(id+" refs/heads/main\x00report-status side-band-64k", id+" refs/heads/dev"),
			adv(id+" refs/heads/main\x00report-status side-band-64k no-thin", id+" refs/heads/dev")},
		{"has it", adv(id + " refs/heads/main\x00report-status no-thin"), adv(id + " refs/heads/main\x00report-status no-thin")},
		{"no capabilities", adv(id + " refs/heads/main"), adv(id + " refs/heads/main")},
		{"only a flush", []byte("0000"), []byte("0000")},
	}
	for _, c := range cases {
		if got := noThin(c.in); string(got) != string(c.out) {
			t.Errorf("%s: noThin = %q, want %q", c.name, got, c.out)
		}
	}
}

func TestRefOID(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	list := adv(a+" refs/heads/main\x00report-status", b+" refs/heads/dev")
	for ref, want := range map[string]string{"refs/heads/dev": b, "refs/heads/gone": ""} {
		if got := refOID(list, ref); got != want {
			t.Errorf("refOID(%s) = %q, want %q", ref, got, want)
		}
	}
}

func TestStale(t *testing.T) {
	a, b, c := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	zero := strings.Repeat("0", 40)
	list := adv(a+" refs/heads/main\x00report-status", b+" refs/heads/dev")
	push := policy.Push{Updates: []policy.RefUpdate{
		{Old: b, New: c, Ref: "refs/heads/dev"},
		{Old: zero, New: c, Ref: "refs/heads/new"},
		{Old: a, New: zero, Ref: "refs/heads/main"},
	}}
	if got := stale(push, list); len(got) != 0 {
		t.Errorf("commands that start from GitHub's commits were refused: %v", got)
	}
	push = policy.Push{Updates: []policy.RefUpdate{
		{Old: c, New: a, Ref: "refs/heads/dev"},
		{Old: c, New: zero, Ref: "refs/heads/main"},
		{Old: zero, New: c, Ref: "refs/heads/dev2"},
		{Old: zero, New: c, Ref: "refs/heads/main"},
		{Old: c, New: zero, Ref: "refs/heads/gone"},
	}}
	got := stale(push, list)
	for ref, want := range map[string]string{
		"refs/heads/dev":  "starts from ccccccc, and GitHub has the branch at bbbbbbb",
		"refs/heads/main": "already has this branch",
		"refs/heads/gone": "doesn't have this branch",
	} {
		if !strings.Contains(got[ref], want) {
			t.Errorf("%s: %q, want %q", ref, got[ref], want)
		}
	}
	if len(got) != 3 {
		t.Errorf("refused %v, want dev, main, and gone only", got)
	}
}

// readAdvertisement takes pkt-lines from the empty one (0004) to the
// longest git allows (65520 bytes), and refuses lengths outside that.
func TestReadAdvertisement(t *testing.T) {
	longest := "fff0" + strings.Repeat("x", 0xfff0-4)
	cases := []struct {
		in string
		ok bool
	}{
		{"0004" + longest + "0000", true},
		{"0003" + "0000", false},
		{"fff1" + strings.Repeat("x", 0xfff1-4) + "0000", false},
	}
	for _, c := range cases {
		got, err := readAdvertisement(bufio.NewReader(strings.NewReader(c.in)))
		if c.ok && (err != nil || string(got) != c.in) || !c.ok && err == nil {
			t.Errorf("readAdvertisement(%.8q) = %.8q, %v", c.in, got, err)
		}
	}
}
