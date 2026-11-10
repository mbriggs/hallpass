package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mbriggs/hallpass/internal/audit"
)

func TestPrintLog(t *testing.T) {
	render := func(f audit.Filter, summary bool) string {
		t.Helper()
		src, err := os.Open("../../internal/audit/testdata/broker.log")
		if err != nil {
			t.Fatal(err)
		}
		defer src.Close()
		var out bytes.Buffer
		if err := printLog(&out, src, f, summary, time.UTC); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	all := render(audit.Filter{}, false)
	if n := strings.Count(all, "\n"); n != 84 {
		t.Errorf("%d lines, want one per record, 84", n)
	}
	refused := render(audit.Filter{Refused: true, Repo: "acme/widgets"}, false)
	t.Log("\n" + refused)
	for l := range strings.SplitSeq(strings.TrimSuffix(refused, "\n"), "\n") {
		if !strings.Contains(l, "  refused  ") || !strings.Contains(l, "acme/widgets") {
			t.Errorf("filtered out: %s", l)
		}
	}
	sum := render(audit.Filter{Refused: true, Repo: "acme/widgets"}, true)
	t.Log("\n" + sum)
	if !strings.Contains(sum, "policy allow push.default --repo acme/widgets") {
		t.Errorf("summary lost the command that allows the push:\n%s", sum)
	}
}
