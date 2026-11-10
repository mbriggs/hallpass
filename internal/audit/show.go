package audit

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// View says how to render records: in which time zone, and whether to color
// them with ANSI escapes.
type View struct {
	Loc   *time.Location
	Color bool
}

// shown are the attrs Line puts in their own places, or leaves out: pid is
// noise next to the process chain.
var shown = map[string]bool{
	"via": true, "uid": true, "pid": true, "procs": true, "repo": true, "now": true,
	"route": true, "graphql": true, "op": true, "object": true,
	"status": true, "exit": true, "reason": true, "refs": true,
	"rejected": true, "rejected_more": true,
}

// Line renders r on one line for a terminal:
//
//	2026-11-10 07:20:08  refused  gh   acme/widgets  PUT pulls/#/merge: agents may not ...  (uid 501: gh < zsh < claude)
//
// Every value goes through clean, so nothing a client sent can reach the
// terminal as a control character. Only Line adds escape sequences, around
// text that is already clean.
func (v View) Line(r Record) string { return v.line(entry{Record: r, count: 1}) }

// entry is what one output line shows: a record, and either the record that
// ends the push it began or the later records that repeat it.
type entry struct {
	Record
	// result is the allowed record that ends a push, folded into its pushed
	// record.
	result *Record
	// count is how many identical records the line stands for, and last is
	// when the last of them was logged.
	count int
	last  time.Time
}

func (v View) line(e entry) string {
	r := e.Record
	t := text{color: v.Color}
	t.add(faint, r.Time.In(v.Loc).Format(time.DateTime))
	via := r.Get("via")
	if via == "" && r.Get("uid") != "" {
		via = "ctl" // the control socket: status and signing
	}
	if via == "" {
		// The broker's own line, not a request: no via, repo, or process.
		msg, st := r.Msg, msgStyle(r)
		if msg == "serving" {
			msg, st = "broker started", bold
		}
		t.add(plain, "  ")
		t.add(st, msg)
		for _, a := range r.Attrs {
			t.add(plain, " "+a.Key+"="+a.Value)
		}
		return t.String()
	}
	t.add(plain, "  ")
	t.pad(msgStyle(r), r.Msg, 7)
	t.add(plain, "  ")
	what := action(r)
	if r.Get("repo") == "" && what == "" {
		t.add(plain, via) // a reason follows it at once
	} else {
		t.pad(plain, via, 3)
	}
	if repo := r.Get("repo"); repo != "" {
		t.add(plain, "  ")
		t.add(cyan, repo)
		if now := r.Get("now"); now != "" {
			t.add(plain, " (now ")
			t.add(cyan, now)
			t.add(plain, ")")
		}
	}
	if what != "" {
		t.add(plain, "  "+what)
	}
	switch {
	case r.Refused():
		t.add(plain, ": ")
		for i, f := range r.Refusals() {
			if i > 0 {
				t.add(plain, "; ")
			}
			if f.Ref != "" {
				t.add(red, f.Ref+": ")
			}
			t.add(red, f.Reason)
		}
	case r.Msg == "failed":
		t.add(plain, ": ")
		t.add(red, r.Get("reason"))
	case isPush(r):
		refs := strings.Trim(r.Get("refs"), "[]")
		rejected, more, ok := r.Rejected()
		switch {
		case !ok:
			t.add(plain, " "+refs)
			t.add(red, " rejected="+r.Get("rejected"))
		case refs == "" && len(rejected) == 0:
			t.add(red, ", GitHub accepted none of the refs")
		case refs != "":
			t.add(plain, " "+refs)
		}
		if len(rejected) > 0 {
			if refs != "" {
				t.add(plain, ";")
			} else {
				t.add(plain, ",")
			}
			t.add(plain, " GitHub rejected ")
			for i, f := range rejected {
				if i > 0 {
					t.add(plain, "; ")
				}
				t.add(red, f.Ref+": "+f.Reason)
			}
			if more > 0 {
				t.add(red, "; and "+strconv.Itoa(more)+" more")
			}
		}
		if e.result != nil {
			result(&t, *e.result)
		}
	default:
		result(&t, r)
	}
	for _, a := range r.Attrs {
		// action says "without a credential" for an anonymous fetch.
		inAction := a.Key == "anonymous" && a.Value == "true" && r.Get("op") == "upload-pack"
		if !shown[a.Key] && !inAction {
			t.add(plain, " "+a.Key+"="+a.Value)
		}
	}
	if e.count > 1 {
		layout := time.TimeOnly
		if e.last.In(v.Loc).YearDay() != r.Time.In(v.Loc).YearDay() || e.last.Year() != r.Time.Year() {
			layout = time.DateTime
		}
		t.add(plain, "  ")
		t.add(bold, "x"+strconv.Itoa(e.count))
		t.add(plain, " until "+e.last.In(v.Loc).Format(layout))
	}
	if uid := r.Get("uid"); uid != "" {
		chain := "(uid " + uid
		if procs := r.Get("procs"); procs != "" {
			chain += ": " + procs
		}
		t.add(plain, "  ")
		t.add(faint, chain+")")
	}
	return t.String()
}

// result writes what came of an allowed request: GitHub's HTTP status, or
// git's exit code. A failure is red.
func result(t *text, r Record) {
	if s := r.Get("status"); s != "" {
		n, err := strconv.Atoi(s)
		t.add(plain, " -> ")
		t.add(failStyle(err != nil || n >= 400), s)
	} else if x := r.Get("exit"); x != "" {
		t.add(plain, " -> ")
		t.add(failStyle(x != "0"), "exit "+x)
	}
}

func failStyle(failed bool) style {
	if failed {
		return red
	}
	return plain
}

func msgStyle(r Record) style {
	switch {
	case r.Refused():
		return boldRed
	case r.Level == "ERROR" || r.Msg == "failed" || r.Msg == "rejected":
		return red
	case r.Msg == "pushed" || r.Msg == "signed":
		return green
	}
	return plain
}

// action names what the client asked for: a REST route, GraphQL fields, a
// git fetch or push, or a signature.
func action(r Record) string {
	switch {
	case r.Get("route") != "":
		return r.Get("route")
	case r.Get("graphql") != "":
		return "graphql " + r.Get("graphql")
	case r.Get("op") == "upload-pack" && r.Get("anonymous") == "true":
		return "fetch without a credential"
	case r.Get("op") == "upload-pack":
		return "fetch"
	case r.Get("op") == "receive-pack":
		return "push"
	case r.Get("object") != "":
		return "sign " + r.Get("object")
	}
	return r.Get("op")
}

// Printer writes records a line each, as Scan hands them over. Unless All
// is set it keeps the output short in three ways that can't hide a refusal:
//
//   - It leaves out allowed status checks on the control socket. git asks
//     for one before every signature, to see whether the key is the
//     broker's.
//   - It folds a push's pushed line and the allowed line that ends the same
//     connection into one.
//   - It collapses a run of identical allowed requests from one process,
//     such as gh pr checks --watch polling, into one line with a count.
type Printer struct {
	View
	All bool

	w       io.Writer
	pending *entry
	shown   int
	hidden  int
}

// NewPrinter returns a Printer that writes to w.
func NewPrinter(w io.Writer, v View, all bool) *Printer {
	return &Printer{View: v, All: all, w: w}
}

// Add takes the next record.
func (p *Printer) Add(r Record) error {
	if p.All {
		return p.write(entry{Record: r, count: 1})
	}
	if routine(r) {
		p.hidden++
		return nil
	}
	if e := p.pending; e != nil {
		switch {
		case endsPush(*e, r):
			e.result = &r
			return nil
		case repeats(*e, r):
			e.count++
			e.last = r.Time
			return nil
		}
	}
	err := p.Flush()
	p.pending = &entry{Record: r, count: 1, last: r.Time}
	return err
}

// Flush writes the line Add is holding back, if any.
func (p *Printer) Flush() error {
	if p.pending == nil {
		return nil
	}
	e := *p.pending
	p.pending = nil
	return p.write(e)
}

func (p *Printer) write(e entry) error {
	p.shown++
	_, err := fmt.Fprintln(p.w, p.line(e))
	return err
}

// Counts reports how many lines the Printer wrote and how many routine
// records it left out.
func (p *Printer) Counts() (shown, hidden int) { return p.shown, p.hidden }

// routine reports whether r is an allowed status check on the control
// socket.
func routine(r Record) bool {
	return r.Msg == "allowed" && r.Get("via") == "" && r.Get("op") == "status"
}

// endsPush reports whether r is the allowed line that closes the push e
// began. The broker logs both from one connection's logger, so every attr
// but the push line's refs and rejections and allowed's exit is the same,
// pid included.
func endsPush(e entry, r Record) bool {
	return isPush(e.Record) && e.result == nil && e.count == 1 &&
		r.Msg == "allowed" && r.Get("op") == "receive-pack" && r.Get("exit") != "" &&
		slices.Equal(without(e.Attrs, "refs", "rejected", "rejected_more"), without(r.Attrs, "exit"))
}

// isPush reports whether r is GitHub's answer to a push the broker
// forwarded: pushed, or rejected when GitHub took none of its refs.
func isPush(r Record) bool { return r.Msg == "pushed" || r.Msg == "rejected" }

// repeats reports whether r repeats e exactly, time aside: an allowed
// request from the same process with the same result.
func repeats(e entry, r Record) bool {
	return e.result == nil && r.Msg == "allowed" && r.Get("pid") != "" &&
		e.Level == r.Level && e.Msg == r.Msg && slices.Equal(e.Attrs, r.Attrs)
}

func without(attrs []Attr, keys ...string) []Attr {
	return slices.DeleteFunc(slices.Clone(attrs), func(a Attr) bool { return slices.Contains(keys, a.Key) })
}

// Group counts the refusals that share a repo and a reason. A refusal with
// no repo files under What instead: the via and what it asked for, as far
// as the log says.
type Group struct {
	Repo   string
	What   string
	Reason string
	Count  int
	Last   time.Time
}

// Summarize groups the refusals in records by repo and reason, most first.
func Summarize(records []Record) []Group {
	type key struct{ repo, what, reason string }
	at := map[key]int{}
	var groups []Group
	for _, r := range records {
		what := ""
		if r.Get("repo") == "" {
			what = request(r)
		}
		for _, f := range r.Refusals() {
			k := key{strings.ToLower(r.Get("repo")), what, f.Reason}
			i, ok := at[k]
			if !ok {
				i = len(groups)
				at[k] = i
				groups = append(groups, Group{Repo: r.Get("repo"), What: what, Reason: f.Reason})
			}
			groups[i].Count++
			if r.Time.After(groups[i].Last) {
				groups[i].Last = r.Time
			}
		}
	}
	slices.SortStableFunc(groups, func(a, b Group) int {
		return cmp.Or(b.Count-a.Count, b.Last.Compare(a.Last))
	})
	return groups
}

// request names a request by its via and action, such as "gh GET
// /search/code" or "ctl".
func request(r Record) string {
	via := r.Get("via")
	if via == "" && r.Get("uid") != "" {
		via = "ctl"
	}
	return strings.TrimSpace(via + " " + action(r))
}

// WriteSummary prints groups, each as a count, repo, and last time, with
// the full reason under it. A reason that names the command that would
// allow the request keeps it.
func (v View) WriteSummary(w io.Writer, groups []Group) error {
	if len(groups) == 0 {
		_, err := fmt.Fprintln(w, "No refusals.")
		return err
	}
	width := 0
	for _, g := range groups {
		_, name := groupName(g)
		width = max(width, utf8.RuneCountInString(clean(name)))
	}
	for _, g := range groups {
		t := text{color: v.Color}
		t.add(bold, fmt.Sprintf("%5d", g.Count))
		t.add(plain, "  ")
		st, name := groupName(g)
		t.pad(st, name, width)
		t.add(plain, "  ")
		t.add(faint, "last "+g.Last.In(v.Loc).Format("2006-01-02 15:04"))
		t.b.WriteString("\n       ")
		t.add(plain, g.Reason)
		if _, err := fmt.Fprintln(w, t.String()); err != nil {
			return err
		}
	}
	return nil
}

func groupName(g Group) (style, string) {
	switch {
	case g.Repo != "":
		return cyan, g.Repo
	case g.What != "":
		return plain, g.What
	}
	return plain, "(no repo)"
}

// style is an SGR parameter list, from the 16 basic colors and attributes
// so it reads on dark and light terminals alike.
type style string

const (
	plain   style = ""
	bold    style = "1"
	faint   style = "2"
	red     style = "31"
	boldRed style = "1;31"
	green   style = "32"
	cyan    style = "36"
)

// text builds a line from cleaned values, and when color is on, wraps each
// styled value in its escape sequence and a reset. Values go through clean
// before the escapes go around them, so a value can't open, close, or change
// a sequence.
type text struct {
	b     strings.Builder
	color bool
}

// add writes s, cleaned, in style st, and returns how many runes it showed.
func (t *text) add(st style, s string) int {
	s = clean(s)
	if t.color && st != plain {
		t.b.WriteString("\x1b[" + string(st) + "m" + s + "\x1b[0m")
	} else {
		t.b.WriteString(s)
	}
	return utf8.RuneCountInString(s)
}

// pad writes s as add does, then spaces out to width runes.
func (t *text) pad(st style, s string, width int) {
	n := t.add(st, s)
	t.b.WriteString(strings.Repeat(" ", max(0, width-n)))
}

func (t *text) String() string { return t.b.String() }

// clean makes s safe to print on a terminal: it escapes every rune that
// isn't printable, as Go would quote it, and every byte that isn't UTF-8.
// That covers C0 and C1 controls, so no escape sequence gets through, and
// format characters such as the bidi overrides that can make text read
// differently from what it is.
func clean(s string) string {
	ok := true
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			ok = false
			break
		}
	}
	if ok {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unicode.IsPrint(r) && r != utf8.RuneError:
			b.WriteRune(r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
		i += n
	}
	return b.String()
}
