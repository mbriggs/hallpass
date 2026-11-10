package audit

import (
	"bytes"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// testdata/broker.log is a scratch broker's log from a verify-hallpass
// drive.sh all run, as the broker writes it to /var/log/hallpass.log and
// journalctl -o cat prints it.
func fixture(t *testing.T) []Record {
	t.Helper()
	f, err := os.Open("testdata/broker.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []Record
	lines, err := Scan(f, Filter{}, func(r Record) { recs = append(recs, r) })
	if err != nil {
		t.Fatal(err)
	}
	if lines != len(recs) {
		t.Fatalf("parsed %d of %d lines", len(recs), lines)
	}
	return recs
}

func TestFixtureParses(t *testing.T) {
	counts := map[string]int{}
	for _, r := range fixture(t) {
		counts[r.Msg]++
	}
	want := map[string]int{"allowed": 37, "refused": 28, "pushed": 4, "signed": 4, "serving": 6,
		"ledger write failed; after a restart agents can't update this branch": 3}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s: %d records, want %d", k, counts[k], v)
		}
	}
}

func TestParseFields(t *testing.T) {
	line := `time=2026-11-10T07:20:08.634-05:00 level=WARN msg=refused via=gh uid=501 pid=36445 procs="gh < bash" repo=acme/widgets route="PUT pulls/#/merge" reason="agents may not merge PRs in acme/widgets. To allow it: sudo /opt/hallpass/bin/hallpass policy allow pr.merge --repo acme/widgets"`
	r, ok := Parse(line)
	if !ok {
		t.Fatal("didn't parse")
	}
	want := time.Date(2026, 11, 10, 12, 20, 8, 634e6, time.UTC)
	if !r.Time.Equal(want) || r.Level != "WARN" || r.Msg != "refused" {
		t.Errorf("got %v %q %q", r.Time, r.Level, r.Msg)
	}
	if r.Get("procs") != "gh < bash" || r.Get("route") != "PUT pulls/#/merge" || r.Get("uid") != "501" {
		t.Errorf("attrs: %+v", r.Attrs)
	}
	got := Line(r, time.UTC)
	wantLine := "2026-11-10 12:20:08  refused  gh   acme/widgets  PUT pulls/#/merge: agents may not merge PRs in acme/widgets. To allow it: sudo /opt/hallpass/bin/hallpass policy allow pr.merge --repo acme/widgets  (uid 501: gh < bash)"
	if got != wantLine {
		t.Errorf("Line:\n got %s\nwant %s", got, wantLine)
	}
}

// The journal holds systemd's own lines for the unit too, and the file can
// hold a panic's trace. They aren't records.
func TestParseSkipsOtherLines(t *testing.T) {
	for _, line := range []string{
		"Started hallpass.service - hallpass credential broker.",
		"-- No entries --",
		"panic: runtime error: index out of range [3] with length 3",
		"goroutine 1 [running]:",
		"\tmain.main()",
		`time=2026-11-10T07:20:08.634-05:00 level=INFO`,
		`time=yesterday level=INFO msg=allowed`,
		`time=2026-11-10T07:20:08.634-05:00 level=INFO msg="unterminated`,
		`time=2026-11-10T07:20:08.634-05:00 level=INFO msg=allowed junk`,
		"",
	} {
		if r, ok := Parse(line); ok {
			t.Errorf("Parse(%q) = %+v, want not a record", line, r)
		}
	}
}

func TestRefusalsOfPush(t *testing.T) {
	line := `time=2026-11-10T07:20:11.203-05:00 level=WARN msg=refused via=ssh uid=501 pid=1 procs=git repo=acme/widgets op=receive-pack reason=push refs="map[refs/heads/main:main is the default branch; push another branch and open a PR. To allow it: sudo /opt/hallpass/bin/hallpass policy allow push.default --repo acme/widgets refs/tags/v1:agents can't push tags]"`
	r, ok := Parse(line)
	if !ok {
		t.Fatal("didn't parse")
	}
	got := r.Refusals()
	want := []Refusal{
		{"refs/heads/main", "main is the default branch; push another branch and open a PR. To allow it: sudo /opt/hallpass/bin/hallpass policy allow push.default --repo acme/widgets"},
		{"refs/tags/v1", "agents can't push tags"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Refusals:\n got %q\nwant %q", got, want)
	}
	if l := Line(r, time.UTC); !strings.Contains(l, "push: refs/heads/main: main is the default branch;") || !strings.Contains(l, "; refs/tags/v1: agents can't push tags") {
		t.Errorf("Line: %s", l)
	}
	// A refs attr in some other form keeps the reason as logged.
	r.Attrs[len(r.Attrs)-1].Value = "something else"
	if got := r.Refusals(); len(got) != 1 || got[0].Reason != "push" {
		t.Errorf("unparsed refs: %q", got)
	}
}

func TestFilter(t *testing.T) {
	recs := fixture(t)
	since, _ := time.Parse(time.RFC3339, "2026-11-10T07:49:35-05:00")
	for _, tc := range []struct {
		name string
		f    Filter
		want int
	}{
		{"all", Filter{}, len(recs)},
		{"refused", Filter{Refused: true}, 28},
		{"repo", Filter{Repo: "acme/readonly"}, 3},
		{"repo in another case", Filter{Repo: "ACME/Readonly"}, 3},
		// 37 lines name it in repo, and one fetch of acme/gadgets names it
		// as the name GitHub has now.
		{"repo by its current name", Filter{Repo: "acme/widgets"}, 38},
		{"repo by its old name", Filter{Repo: "acme/gadgets"}, 1},
		{"refused in repo", Filter{Refused: true, Repo: "acme/readonly"}, 2},
		{"since", Filter{Since: since}, 41},
		{"refused since", Filter{Refused: true, Since: since}, 8},
	} {
		n := 0
		for _, r := range recs {
			if tc.f.Match(r) {
				n++
			}
		}
		if n != tc.want {
			t.Errorf("%s: %d records, want %d", tc.name, n, tc.want)
		}
	}
}

func TestSummary(t *testing.T) {
	var refused []Record
	for _, r := range fixture(t) {
		if r.Refused() {
			refused = append(refused, r)
		}
	}
	groups := Summarize(refused)
	total := 0
	for _, g := range groups {
		total += g.Count
	}
	if total != 28 {
		t.Errorf("groups count %d refusals, want 28", total)
	}
	var buf bytes.Buffer
	if err := WriteSummary(&buf, groups, time.UTC); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Log("\n" + out)
	for _, want := range []string{
		"sudo /opt/hallpass/bin/hallpass policy allow pr.merge --repo acme/widgets",
		"sudo /opt/hallpass/bin/hallpass policy allow push.default --repo acme/widgets",
		"release/1 is protected in hallpass's config",
		"(no repo)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q", want)
		}
	}
	for i := 1; i < len(groups); i++ {
		if groups[i].Count > groups[i-1].Count {
			t.Errorf("groups out of order at %d", i)
		}
	}
	// gh pr merge and gh pr review --approve name the PR by node ID. Their
	// refusals file under the repo the ID resolved to.
	for _, op := range []string{"pr.merge", "review.verdict"} {
		found := false
		for _, g := range groups {
			if strings.Contains(g.Reason, "policy allow "+op+" ") {
				found = true
				if g.Repo != "acme/widgets" {
					t.Errorf("%s refusal filed under %q", op, g.Repo)
				}
			}
		}
		if !found {
			t.Errorf("no %s refusal", op)
		}
	}
}

// A GraphQL request that touches several repos logs them joined by commas.
// --repo matches any of them, and the summary keeps the set together.
func TestMultiRepo(t *testing.T) {
	r, ok := Parse(`time=2026-11-10T07:20:08Z level=WARN msg=refused via=gh uid=501 pid=1 procs=gh graphql=repository,node repo=acme/widgets,acme/secret reason="node is in acme/secret, which isn't in hallpass's allowlist"`)
	if !ok {
		t.Fatal("didn't parse")
	}
	for repo, want := range map[string]bool{"acme/widgets": true, "ACME/secret": true, "acme/widgets,acme/secret": false, "acme/w": false} {
		if got := (Filter{Repo: repo}).Match(r); got != want {
			t.Errorf("--repo %s: %v, want %v", repo, got, want)
		}
	}
	g := Summarize([]Record{r, r})
	if len(g) != 1 || g[0].Repo != "acme/widgets,acme/secret" || g[0].Count != 2 {
		t.Errorf("summary: %+v", g)
	}
	if l := Line(r, time.UTC); !strings.Contains(l, "  acme/widgets,acme/secret  graphql repository,node: node is in") {
		t.Errorf("Line: %s", l)
	}
}

func TestSummaryCounts(t *testing.T) {
	at := func(m int) time.Time { return time.Date(2026, 11, 10, 9, m, 0, 0, time.UTC) }
	rec := func(m int, repo, reason string) Record {
		return Record{Time: at(m), Level: "WARN", Msg: "refused", Attrs: []Attr{{"repo", repo}, {"reason", reason}}}
	}
	got := Summarize([]Record{
		rec(1, "acme/a", "no"),
		rec(2, "acme/b", "no"),
		rec(3, "ACME/A", "no"),
		rec(4, "acme/a", "never"),
		{Time: at(5), Msg: "allowed", Attrs: []Attr{{"repo", "acme/a"}}},
	})
	want := []Group{
		{Repo: "acme/a", Reason: "no", Count: 2, Last: at(3)},
		{Repo: "acme/a", Reason: "never", Count: 1, Last: at(4)},
		{Repo: "acme/b", Reason: "no", Count: 1, Last: at(2)},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// hostile are values a client could get into the log: escape sequences
// that set a terminal's title, move its cursor, or clear it, a carriage
// return that hides what came before, bidi overrides, invalid UTF-8, and a
// newline with a forged record after it.
var hostile = []string{
	"\x1b]0;pwned\x07git push",
	"\x1b[2J\x1b[Hall clear",
	"ok\rrefused",
	"\u009b31m C1 CSI",
	"evil\u202egnp.exe",
	"bad \xff\xfe utf8",
	"line\ntime=2026-11-10T00:00:00Z level=INFO msg=allowed repo=acme/widgets",
	"tab\there",
	"zero\x00width\u200b",
	`quote" and \ backslash`,
	"=",
	"",
}

// TestHostileRoundTrip writes hostile values through the broker's own
// handler, then checks the reader gets them back intact and never prints
// one raw.
func TestHostileRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	for _, v := range hostile {
		log.Warn("refused", "via", "gh", "uid", 501, "procs", v, "repo", v, "route", v, "reason", v, v, v)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != len(hostile) {
		t.Fatalf("%d lines for %d records: a value split a line", len(lines), len(hostile))
	}
	var recs []Record
	for i, line := range lines {
		r, ok := Parse(line)
		if !ok {
			t.Fatalf("line %d didn't parse: %q", i, line)
		}
		v := hostile[i]
		for _, k := range []string{"procs", "repo", "route", "reason"} {
			if r.Get(k) != v {
				t.Errorf("%s = %q, want %q", k, r.Get(k), v)
			}
		}
		recs = append(recs, r)
		assertPrintable(t, Line(r, time.UTC))
	}
	var sum bytes.Buffer
	if err := WriteSummary(&sum, Summarize(recs), time.UTC); err != nil {
		t.Fatal(err)
	}
	for l := range strings.SplitSeq(strings.TrimSuffix(sum.String(), "\n"), "\n") {
		assertPrintable(t, l)
	}
}

// assertPrintable fails if s holds anything but printable runes.
func assertPrintable(t *testing.T, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Errorf("invalid UTF-8 in %q", s)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || r == utf8.RuneError {
			t.Errorf("unprintable %U in %q", r, s)
			return
		}
	}
}

func TestCleanKeepsPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"gh pr list < claude": "gh pr list < claude",
		"café ✓":              "café ✓",
		"\x1b[31mred":         `\u001b[31mred`,
		"a\x00b":              `a\u0000b`,
		"\xff":                `\xff`,
		"\u202e":              `\u202e`,
		"\U000e0001 tag":      `\U000e0001 tag`,
		"\u009b":              `\u009b`,
		"\r":                  `\u000d`,
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanSkipsLongLines(t *testing.T) {
	good := `time=2026-11-10T07:20:08.634-05:00 level=INFO msg=allowed via=gh`
	in := good + "\n" + "time=" + strings.Repeat("x", maxLine+10) + "\n" + good
	var n int
	lines, err := Scan(strings.NewReader(in), Filter{}, func(Record) { n++ })
	if err != nil || lines != 3 || n != 2 {
		t.Errorf("lines %d, records %d, err %v; want 3, 2, nil", lines, n, err)
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"2h":                        now.Add(-2 * time.Hour),
		"90m":                       now.Add(-90 * time.Minute),
		"3d":                        now.AddDate(0, 0, -3),
		"2026-11-01":                time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		"2026-11-01 14:00":          time.Date(2026, 11, 1, 14, 0, 0, 0, time.UTC),
		"2026-11-01T14:00:00-05:00": time.Date(2026, 11, 1, 19, 0, 0, 0, time.UTC),
	} {
		got, err := ParseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "yesterday", "-2h", "2x", "d"} {
		if _, err := ParseSince(in, now); err == nil {
			t.Errorf("ParseSince(%q) took it", in)
		}
	}
}

func FuzzParse(f *testing.F) {
	data, err := os.ReadFile("testdata/broker.log")
	if err != nil {
		f.Fatal(err)
	}
	for l := range strings.SplitSeq(string(data), "\n") {
		f.Add(l)
	}
	for _, v := range hostile {
		f.Add(`time=2026-11-10T07:20:08Z level=WARN msg=refused reason=push refs="map[refs/heads/` + v + `:` + v + `]"`)
	}
	f.Fuzz(func(t *testing.T, line string) {
		r, ok := Parse(line)
		if !ok {
			return
		}
		assertPrintable(t, Line(r, time.UTC))
		var buf bytes.Buffer
		_ = WriteSummary(&buf, Summarize([]Record{r}), time.UTC)
		for l := range strings.SplitSeq(strings.TrimSuffix(buf.String(), "\n"), "\n") {
			assertPrintable(t, l)
		}
	})
}
