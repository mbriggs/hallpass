package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mbriggs/hallpass/internal/audit"
)

var utc = audit.View{Loc: time.UTC}

func TestPrintLog(t *testing.T) {
	render := func(f audit.Filter, o logOpts) string {
		t.Helper()
		src, err := os.Open("../../internal/audit/testdata/broker.log")
		if err != nil {
			t.Fatal(err)
		}
		defer src.Close()
		var out bytes.Buffer
		if err := printLog(&out, src, f, o); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	all := render(audit.Filter{}, logOpts{view: utc, all: true})
	if n := strings.Count(all, "\n"); n != 85 {
		t.Errorf("%d lines, want one per record with --all, 85", n)
	}
	refused := render(audit.Filter{Refused: true, Repo: "acme/widgets"}, logOpts{view: utc})
	t.Log("\n" + refused)
	for l := range strings.SplitSeq(strings.TrimSuffix(refused, "\n"), "\n") {
		if !strings.Contains(l, "  refused  ") || !strings.Contains(l, "acme/widgets") {
			t.Errorf("filtered out: %s", l)
		}
	}
	sum := render(audit.Filter{Refused: true, Repo: "acme/widgets"}, logOpts{view: utc, summary: true})
	t.Log("\n" + sum)
	if !strings.Contains(sum, "policy allow push.default --repo acme/widgets") {
		t.Errorf("summary lost the command that allows the push:\n%s", sum)
	}
	// Hiding routine lines is for the line view; the summary counts the same.
	if all := render(audit.Filter{Refused: true}, logOpts{view: utc, summary: true, all: true}); all != render(audit.Filter{Refused: true}, logOpts{view: utc, summary: true}) {
		t.Errorf("--all changed the summary:\n%s", all)
	}
}

func TestUseColor(t *testing.T) {
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i+1 < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	for _, tc := range []struct {
		when string
		tty  bool
		env  func(string) string
		want bool
	}{
		{"auto", true, env("TERM", "xterm-256color"), true},
		{"auto", false, env("TERM", "xterm-256color"), false},
		{"auto", true, env("TERM", "xterm", "NO_COLOR", "1"), false},
		{"auto", true, env("TERM", "xterm", "NO_COLOR", ""), true},
		{"auto", true, env("TERM", "dumb"), false},
		{"always", false, env("NO_COLOR", "1"), true},
		{"never", true, env(), false},
	} {
		got, err := useColor(tc.when, tc.tty, tc.env)
		if err != nil || got != tc.want {
			t.Errorf("useColor(%q, tty %v) = %v, %v; want %v", tc.when, tc.tty, got, err, tc.want)
		}
	}
	if _, err := useColor("yes", true, env()); err == nil {
		t.Error("useColor took yes")
	}
}
