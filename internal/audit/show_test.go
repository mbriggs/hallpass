package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// render feeds the log lines in src through a Printer and returns what it
// wrote.
func render(t *testing.T, src string, v View, all bool) string {
	t.Helper()
	var out bytes.Buffer
	p := NewPrinter(&out, v, all)
	var werr error
	_, err := Scan(strings.NewReader(src), Filter{}, func(r Record) {
		if werr == nil {
			werr = p.Add(r)
		}
	})
	if err != nil || werr != nil {
		t.Fatal(err, werr)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func summary(t *testing.T, src string, v View) string {
	t.Helper()
	var recs []Record
	if _, err := Scan(strings.NewReader(src), Filter{Refused: true}, func(r Record) { recs = append(recs, r) }); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := v.WriteSummary(&out, Summarize(recs)); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// testdata/sample.log holds the lines from a user's real log that this
// rendering was shaped on.
func TestSampleOutput(t *testing.T) {
	src := readFile(t, "testdata/sample.log")
	got := render(t, src, utc, false)
	want := `2026-11-10 08:03:42  signed   ctl  sign commit "wip protected paths"  (uid 501: hallpass < git < zsh < 2.1.322 < zsh)
2026-11-10 08:11:39  refused  ssh  rubysec/ruby-advisory-db  fetch: rubysec/ruby-advisory-db isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow rubysec/ruby-advisory-db  (uid 501: hallpass < git < ruby < ruby < zsh)
2026-11-10 08:19:14  pushed   ssh  mbriggs/hallpass  push refs/heads/worktree-agent-ae346336cc682db5b -> exit 0  (uid 501: hallpass < git < bash < zsh < 2.1.322)
2026-11-10 08:19:23  allowed  gh   graphql node -> 200  x3 until 08:19:44  (uid 501: gh < hallpass < zsh < 2.1.322 < zsh)
2026-11-10 08:40:01  refused  gh   GET /search/code (anonymous): Without a token, GitHub answered 401 Unauthorized. hallpass doesn't allow GET /search/code  (uid 501: gh < zsh < 2.1.322 < zsh)
2026-11-10 08:52:01  refused  gh   GET /search/code (anonymous): Without a token, GitHub answered 401 Unauthorized. hallpass doesn't allow GET /search/code  (uid 501: gh < zsh < 2.1.322 < zsh)
2026-11-10 09:02:36  broker started token=true ssh=true signing=true repos=4
2026-11-10 09:03:10  refused  gh   GET /search/code (anonymous): Without a token, GitHub answered 401 Unauthorized. hallpass doesn't allow GET /search/code  (uid 501: gh < zsh < 2.1.322 < zsh)
2026-11-10 09:03:20  refused  ctl: malformed request  (uid 501: python3 < zsh)
2026-11-10 09:10:05  pushed   ssh  mbriggs/hallpass  push refs/heads/agent/a; GitHub rejected refs/heads/agent/b: protected branch hook declined -> exit 0  (uid 501: hallpass < git < bash < zsh < 2.1.322)
2026-11-10 09:11:40  rejected  ssh  mbriggs/hallpass  push, GitHub rejected refs/heads/agent/a: non-fast-forward -> exit 0  (uid 501: hallpass < git < bash < zsh < 2.1.322)
2026-11-10 09:12:00  failed   ssh  mbriggs/hallpass  push: couldn't read GitHub's ref list: EOF  (uid 501: hallpass < git < bash < zsh < 2.1.322)
`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	gotSum := summary(t, src, utc)
	wantSum := `    3  gh GET /search/code (anonymous)  last 2026-11-10 09:03
       Without a token, GitHub answered 401 Unauthorized. hallpass doesn't allow GET /search/code
    1  ctl                              last 2026-11-10 09:03
       malformed request
    1  rubysec/ruby-advisory-db         last 2026-11-10 08:11
       rubysec/ruby-advisory-db isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow rubysec/ruby-advisory-db
`
	if gotSum != wantSum {
		t.Errorf("summary: got\n%s\nwant\n%s", gotSum, wantSum)
	}
	if all := render(t, src, utc, true); strings.Count(all, "\n") != strings.Count(src, "\n") {
		t.Errorf("--all should print a line per record:\n%s", all)
	}
}

// logLine builds a log line at second s, msg, and attrs.
func logLine(s int, level, msg, attrs string) string {
	return "time=" + time.Date(2026, 11, 10, 8, 0, s, 0, time.UTC).Format(time.RFC3339Nano) + " " +
		"level=" + level + " msg=" + msg + " " + attrs + "\n"
}

// The quiet view may leave lines out and join lines, but never drop a
// refusal or join two requests.
func TestQuietView(t *testing.T) {
	conn := func(pid string) string {
		return "via=ssh uid=501 pid=" + pid + ` procs="hallpass < git" repo=acme/widgets op=receive-pack`
	}
	poll := `via=gh uid=501 pid=7 procs=gh graphql=node`
	for _, tc := range []struct {
		name string
		log  []string
		want []string // a substring of each line, in order
	}{
		{"routine status hidden, refused status kept",
			[]string{
				logLine(0, "INFO", "allowed", "uid=501 pid=1 procs=git op=status check=false"),
				logLine(1, "WARN", "refused", `uid=502 pid=2 procs=git reason="uid not permitted"`),
				logLine(2, "WARN", "refused", `uid=501 pid=3 procs=git op=sign reason="hallpass only signs unsigned git commits and tags"`),
			},
			[]string{"refused  ctl: uid not permitted", "refused  ctl  sign: hallpass only signs"}},
		{"a push folds",
			[]string{
				logLine(0, "INFO", "pushed", conn("1")+` refs="[refs/heads/a refs/heads/b]"`),
				logLine(0, "INFO", "allowed", conn("1")+" exit=0"),
			},
			[]string{"pushed   ssh  acme/widgets  push refs/heads/a refs/heads/b -> exit 0"}},
		{"a failed push keeps its exit code",
			[]string{
				logLine(0, "INFO", "pushed", conn("1")+" refs=[refs/heads/a]"),
				logLine(0, "INFO", "allowed", conn("1")+" exit=1"),
			},
			[]string{"push refs/heads/a -> exit 1"}},
		{"a push GitHub rejected part of shows both, and the rest it left out",
			[]string{
				logLine(0, "WARN", "pushed", conn("1")+` refs=[refs/heads/a] rejected="[{\"ref\":\"refs/heads/b\",\"reason\":\"no\"},{\"ref\":\"refs/heads/c\",\"reason\":\"a: b; c\"}]" rejected_more=4`),
				logLine(0, "INFO", "allowed", conn("1")+" exit=0"),
			},
			[]string{"push refs/heads/a; GitHub rejected refs/heads/b: no; refs/heads/c: a: b; c; and 4 more -> exit 0"}},
		{"a rejection from another process doesn't fold",
			[]string{
				logLine(0, "WARN", "rejected", conn("1")+` refs=[] rejected="[{\"ref\":\"refs/heads/b\",\"reason\":\"no\"}]"`),
				logLine(0, "INFO", "allowed", conn("2")+" exit=0"),
			},
			[]string{"rejected  ssh  acme/widgets  push, GitHub rejected refs/heads/b: no  (uid", "push -> exit 0"}},
		{"a rejected attr that isn't JSON shows as logged",
			[]string{logLine(0, "WARN", "pushed", conn("1")+` refs=[refs/heads/a] rejected="map[refs/heads/b:no]"`)},
			[]string{"push refs/heads/a rejected=map[refs/heads/b:no]"}},
		{"a push GitHub rejected says so",
			[]string{
				logLine(0, "INFO", "pushed", conn("1")+" refs=[]"),
				logLine(0, "INFO", "allowed", conn("1")+" exit=0"),
			},
			[]string{"push, GitHub accepted none of the refs -> exit 0"}},
		{"two pushes in one second from two processes stay apart",
			[]string{
				logLine(0, "INFO", "pushed", conn("1")+" refs=[refs/heads/a]"),
				logLine(0, "INFO", "pushed", conn("2")+" refs=[refs/heads/b]"),
				logLine(0, "INFO", "allowed", conn("1")+" exit=0"),
				logLine(0, "INFO", "allowed", conn("2")+" exit=1"),
			},
			[]string{"push refs/heads/a  (uid", "push refs/heads/b  (uid", "push -> exit 0", "push -> exit 1"}},
		{"a hidden status check doesn't stop a fold",
			[]string{
				logLine(0, "INFO", "pushed", conn("1")+" refs=[refs/heads/a]"),
				logLine(0, "INFO", "allowed", "uid=501 pid=9 procs=git op=status check=false"),
				logLine(0, "INFO", "allowed", conn("1")+" exit=0"),
			},
			[]string{"push refs/heads/a -> exit 0"}},
		{"a refused push and a probe push stand alone",
			[]string{
				logLine(0, "WARN", "refused", conn("1")+` reason=push refs="map[refs/heads/main:agents can't delete the default branch]"`),
				logLine(0, "INFO", "allowed", conn("1")+" exit=0"),
			},
			[]string{"push: refs/heads/main: agents can't delete", "push -> exit 0"}},
		{"a fetch without a credential says so",
			[]string{
				logLine(0, "INFO", "allowed", `via=ssh uid=501 pid=1 procs=git repo=octo/public op=upload-pack anonymous=true exit=0`),
				logLine(1, "WARN", "refused", `via=ssh uid=501 pid=2 procs=git repo=octo/gone op=upload-pack anonymous=true reason="GitHub answered 404"`),
			},
			[]string{"allowed  ssh  octo/public  fetch without a credential -> exit 0  (uid 501: git)",
				"refused  ssh  octo/gone  fetch without a credential: GitHub answered 404  (uid"}},
		{"a fetch is one line already",
			[]string{logLine(0, "INFO", "allowed", `via=ssh uid=501 pid=1 procs=git repo=acme/widgets op=upload-pack exit=0`)},
			[]string{"allowed  ssh  acme/widgets  fetch -> exit 0  (uid 501: git)"}},
		{"polling collapses",
			[]string{
				logLine(0, "INFO", "allowed", poll+" status=200"),
				logLine(10, "INFO", "allowed", poll+" status=200"),
				logLine(20, "INFO", "allowed", "uid=501 pid=9 procs=git op=status check=false"),
				logLine(30, "INFO", "allowed", poll+" status=200"),
			},
			[]string{"08:00:00  allowed  gh   graphql node -> 200  x3 until 08:00:30"}},
		{"polling with another result, process, or request in between doesn't",
			[]string{
				logLine(0, "INFO", "allowed", poll+" status=200"),
				logLine(10, "INFO", "allowed", poll+" status=502"),
				logLine(20, "INFO", "allowed", `via=gh uid=501 pid=8 procs=gh graphql=node status=200`),
				logLine(30, "INFO", "allowed", poll+" status=200"),
				logLine(40, "INFO", "allowed", `via=gh uid=501 pid=7 procs=gh graphql=repository repo=acme/widgets status=200`),
			},
			[]string{"node -> 200  (uid", "node -> 502", "node -> 200  (uid", "node -> 200  (uid", "graphql repository"}},
		{"identical refusals each keep a line",
			[]string{
				logLine(0, "WARN", "refused", poll+` reason="no"`),
				logLine(10, "WARN", "refused", poll+` reason="no"`),
			},
			[]string{"node: no", "node: no"}},
		{"the broker's own lines",
			[]string{
				logLine(0, "INFO", "serving", "token=true ssh=false signing=true repos=4"),
				logLine(1, "INFO", `"reaching GitHub over SSH"`, "addr=127.0.0.1:22"),
			},
			[]string{"08:00:00  broker started token=true ssh=false", "08:00:01  reaching GitHub over SSH addr=127.0.0.1:22"}},
	} {
		got := strings.Split(strings.TrimSuffix(render(t, strings.Join(tc.log, ""), utc, false), "\n"), "\n")
		if len(got) != len(tc.want) {
			t.Errorf("%s: %d lines, want %d:\n%s", tc.name, len(got), len(tc.want), strings.Join(got, "\n"))
			continue
		}
		for i, w := range tc.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: line %d is\n  %s\nwant it to hold\n  %s", tc.name, i, got[i], w)
			}
		}
	}
}

// Quiet or not, the fixture's refusals all show, and the quiet view leaves
// out only routine status checks and lines it joined to another.
func TestQuietFixture(t *testing.T) {
	src := readFile(t, "testdata/broker.log")
	all := render(t, src, utc, true)
	quiet := render(t, src, utc, false)
	if strings.Count(all, "  refused  ") != 28 || strings.Count(quiet, "  refused  ") != 28 {
		t.Errorf("refusals: %d with --all, %d without, want 28", strings.Count(all, "  refused  "), strings.Count(quiet, "  refused  "))
	}
	if strings.Contains(quiet, "  status") {
		t.Errorf("a routine status check showed:\n%s", quiet)
	}
	// 85 records, less 18 status checks and 4 push endings folded in.
	if n := strings.Count(quiet, "\n"); n != 85-18-4 {
		t.Errorf("%d lines, want 63:\n%s", n, quiet)
	}
	if n := strings.Count(quiet, "push refs/heads/agent/fix -> exit 0"); n != 3 {
		t.Errorf("%d folded pushes of agent/fix, want 3", n)
	}
}

// sgr matches the escape sequences the palette writes.
var sgr = regexp.MustCompile("\x1b\\[(?:0|1|2|31|1;31|32|36)m")

// Color changes nothing but the escapes around values: take them out and
// the text is what it is with color off. And no value can add, end, or
// change a sequence, since each value is cleaned before the escapes go on.
func TestColor(t *testing.T) {
	color := View{Loc: time.UTC, Color: true}
	var hostileLog strings.Builder
	for _, v := range hostile {
		rejected, _ := json.Marshal([]Refusal{{Ref: v, Reason: v}})
		for _, msg := range []string{"refused", "allowed", "pushed", "rejected", "failed"} {
			hostileLog.WriteString(logLine(0, "WARN", msg, "via="+strconv.Quote(v)+" uid=501 pid=1 procs="+strconv.Quote(v)+" repo="+strconv.Quote(v)+
				" route="+strconv.Quote(v)+" reason="+strconv.Quote(v)+" refs="+strconv.Quote("map[refs/heads/"+v+":"+v+"]")+" status="+strconv.Quote(v)+
				" rejected="+strconv.Quote(string(rejected))+" rejected_more="+strconv.Quote(v)+" "+strconv.Quote(v+"k")+"="+strconv.Quote(v)))
		}
		hostileLog.WriteString(logLine(0, "INFO", "serving", strconv.Quote(v+"k")+"="+strconv.Quote(v)))
	}
	for _, src := range []string{readFile(t, "testdata/broker.log"), readFile(t, "testdata/sample.log"), hostileLog.String()} {
		for _, all := range []bool{true, false} {
			check(t, render(t, src, color, all), render(t, src, utc, all))
		}
		check(t, summary(t, src, color), summary(t, src, utc))
	}
	// The palette: refusals, repos, and the time and process chain.
	line := color.Line(fixture(t)[5])
	for _, want := range []string{"\x1b[2m2026-", "\x1b[1;31mrefused\x1b[0m", "\x1b[36macme/widgets\x1b[0m", "\x1b[31magents may not merge", "\x1b[2m(uid 501: gh < bash"} {
		if !strings.Contains(line, want) {
			t.Errorf("colored line lacks %q:\n%q", want, line)
		}
	}
}

// check fails unless colored is plain with escapes added, each opened and
// reset in turn, and nothing else unprintable.
func check(t *testing.T, colored, plain string) {
	t.Helper()
	if got := sgr.ReplaceAllString(colored, ""); got != plain {
		t.Errorf("colored output, escapes removed, differs from plain:\n%q\n%q", got, plain)
		return
	}
	open := false
	for _, m := range sgr.FindAllString(colored, -1) {
		reset := m == "\x1b[0m"
		if reset != open {
			t.Errorf("escapes out of turn at %q in %q", m, colored)
			return
		}
		open = !reset
	}
	if open {
		t.Errorf("a style is left open: %q", colored)
	}
	for l := range strings.SplitSeq(strings.TrimSuffix(plain, "\n"), "\n") {
		assertPrintable(t, l)
	}
}
