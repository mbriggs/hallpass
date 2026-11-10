package sshgate

import (
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mbriggs/hallpass/internal/audit"
	"github.com/mbriggs/hallpass/internal/policy"
)

// logged runs logReport and parses the line it wrote the way hallpass log
// does.
func logged(t *testing.T, rep policy.Report) audit.Record {
	t.Helper()
	var buf bytes.Buffer
	logReport(slog.New(slog.NewTextHandler(&buf, nil)).With("via", "ssh", "repo", "acme/widgets", "op", "receive-pack"), rep)
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("logReport wrote %q, want one line", buf.String())
	}
	r, ok := audit.Parse(buf.String())
	if !ok {
		t.Fatalf("hallpass log can't parse %q", buf.String())
	}
	return r
}

func TestLogReport(t *testing.T) {
	// GitHub's reason is text from the network: spaces, colons, quotes,
	// brackets, JSON of its own, control characters, and invalid UTF-8.
	hostile := `pre-receive hook declined: "x" map[refs/heads/a:b] [{"ref":"forged"}] ` + "\x1b[31m\r\n\xff"
	for _, tc := range []struct {
		name         string
		rep          policy.Report
		level, msg   string
		refs         string
		rejected     []audit.Refusal
		rejectedMore int
	}{
		{"accepted", policy.Report{Accepted: []string{"refs/heads/a", "refs/heads/b"}}, "INFO", "pushed", "[refs/heads/a refs/heads/b]", nil, 0},
		{"none either way", policy.Report{}, "INFO", "pushed", "[]", nil, 0},
		{"partly rejected",
			policy.Report{Accepted: []string{"refs/heads/a"}, Rejected: []policy.Rejection{{Ref: "refs/heads/b", Reason: hostile}}},
			"WARN", "pushed", "[refs/heads/a]", []audit.Refusal{{Ref: "refs/heads/b", Reason: strings.ToValidUTF8(hostile, "�")}}, 0},
		{"wholly rejected",
			policy.Report{Rejected: []policy.Rejection{{Ref: "refs/heads/b", Reason: "non-fast-forward"}, {Ref: "refs/heads/c"}}},
			"WARN", "rejected", "[]", []audit.Refusal{{Ref: "refs/heads/b", Reason: "non-fast-forward"}, {Ref: "refs/heads/c"}}, 0},
	} {
		r := logged(t, tc.rep)
		if r.Level != tc.level || r.Msg != tc.msg || r.Get("refs") != tc.refs {
			t.Errorf("%s: level=%s msg=%s refs=%s, want %s %s %s", tc.name, r.Level, r.Msg, r.Get("refs"), tc.level, tc.msg, tc.refs)
		}
		got, more, ok := r.Rejected()
		if !ok || more != tc.rejectedMore || fmt.Sprint(got) != fmt.Sprint(tc.rejected) {
			t.Errorf("%s: rejected %q, %d more, ok %v; want %q", tc.name, got, more, ok, tc.rejected)
		}
		if r.Refused() {
			t.Errorf("%s: GitHub's rejection reads as a hallpass refusal", tc.name)
		}
	}
}

// One push can name many refs, and GitHub's reasons can be long, so the
// line stays bounded: the first maxRejected refs, each cut short, then a
// count of the rest.
func TestLogReportBounds(t *testing.T) {
	var rep policy.Report
	long := strings.Repeat("é", 1000) // two bytes each, so a cut can split one
	for i := range maxRejected + 5 {
		rep.Rejected = append(rep.Rejected, policy.Rejection{Ref: "refs/heads/" + strings.Repeat("r", 500) + strconv.Itoa(i), Reason: long})
	}
	var buf bytes.Buffer
	logReport(slog.New(slog.NewTextHandler(&buf, nil)), rep)
	if n := buf.Len(); n > maxRejected*(maxRejectRef+maxRejectWhy+50)+200 {
		t.Errorf("line is %d bytes", n)
	}
	r, _ := audit.Parse(buf.String())
	got, more, ok := r.Rejected()
	if !ok || len(got) != maxRejected || more != 5 {
		t.Fatalf("%d rejected, %d more, ok %v; want %d, 5", len(got), more, ok, maxRejected)
	}
	for _, f := range got {
		if len(f.Ref) > maxRejectRef || len(f.Reason) > maxRejectWhy || !utf8.ValidString(f.Reason) ||
			!strings.HasSuffix(f.Reason, truncatedMark) || !strings.HasSuffix(f.Ref, truncatedMark) {
			t.Errorf("not cut to bounds: %d-byte ref, %d-byte reason %q", len(f.Ref), len(f.Reason), f.Reason[len(f.Reason)-8:])
		}
	}
}
