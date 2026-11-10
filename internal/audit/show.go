package audit

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// shown are the attrs Line puts in their own places, or leaves out: pid is
// noise next to the process chain.
var shown = map[string]bool{
	"via": true, "uid": true, "pid": true, "procs": true, "repo": true, "now": true,
	"route": true, "graphql": true, "op": true, "object": true,
	"status": true, "exit": true, "reason": true, "refs": true,
}

// Line renders r on one line for a terminal, in loc's time:
//
//	2026-11-10 07:20:08  refused  gh   acme/widgets  PUT pulls/#/merge: agents may not ...  (uid 501: gh < zsh < claude)
//
// Every value goes through clean, so nothing a client sent can reach the
// terminal as a control character.
func Line(r Record, loc *time.Location) string {
	var b strings.Builder
	via := r.Get("via")
	if via == "" && r.Get("uid") != "" {
		via = "ctl" // the control socket: status and signing
	}
	fmt.Fprintf(&b, "%s  %-7s  %-3s", r.Time.In(loc).Format(time.DateTime), clean(r.Msg), clean(via))
	if repo := r.Get("repo"); repo != "" {
		b.WriteString("  " + clean(repo))
		if now := r.Get("now"); now != "" {
			b.WriteString(" (now " + clean(now) + ")")
		}
	}
	if what := action(r); what != "" {
		b.WriteString("  " + clean(what))
	}
	switch {
	case r.Refused():
		var why []string
		for _, f := range r.Refusals() {
			if f.Ref != "" {
				why = append(why, clean(f.Ref)+": "+clean(f.Reason))
			} else {
				why = append(why, clean(f.Reason))
			}
		}
		b.WriteString(": " + strings.Join(why, "; "))
	case r.Msg == "pushed":
		b.WriteString(" " + clean(strings.Trim(r.Get("refs"), "[]")))
	case r.Get("status") != "":
		b.WriteString(" -> " + clean(r.Get("status")))
	case r.Get("exit") != "":
		b.WriteString(" -> exit " + clean(r.Get("exit")))
	}
	for _, a := range r.Attrs {
		if !shown[a.Key] {
			b.WriteString(" " + clean(a.Key) + "=" + clean(a.Value))
		}
	}
	if uid := r.Get("uid"); uid != "" {
		b.WriteString("  (uid " + clean(uid))
		if procs := r.Get("procs"); procs != "" {
			b.WriteString(": " + clean(procs))
		}
		b.WriteString(")")
	}
	return b.String()
}

// action names what the client asked for: a REST route, GraphQL fields, a
// git fetch or push, or a signature.
func action(r Record) string {
	switch {
	case r.Get("route") != "":
		return r.Get("route")
	case r.Get("graphql") != "":
		return "graphql " + r.Get("graphql")
	case r.Get("op") == "upload-pack":
		return "fetch"
	case r.Get("op") == "receive-pack":
		return "push"
	case r.Get("object") != "":
		return "sign " + r.Get("object")
	}
	return r.Get("op")
}

// Group counts the refusals that share a repo and a reason.
type Group struct {
	Repo   string
	Reason string
	Count  int
	Last   time.Time
}

// Summarize groups the refusals in records by repo and reason, most first.
func Summarize(records []Record) []Group {
	type key struct{ repo, reason string }
	at := map[key]int{}
	var groups []Group
	for _, r := range records {
		for _, f := range r.Refusals() {
			k := key{strings.ToLower(r.Get("repo")), f.Reason}
			i, ok := at[k]
			if !ok {
				i = len(groups)
				at[k] = i
				groups = append(groups, Group{Repo: r.Get("repo"), Reason: f.Reason})
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

// WriteSummary prints groups, each as a count, repo, and last time, with
// the full reason under it. A reason that names the command that would
// allow the request keeps it.
func WriteSummary(w io.Writer, groups []Group, loc *time.Location) error {
	if len(groups) == 0 {
		_, err := fmt.Fprintln(w, "No refusals.")
		return err
	}
	width := 0
	for _, g := range groups {
		width = max(width, utf8.RuneCountInString(repoName(g.Repo)))
	}
	for _, g := range groups {
		if _, err := fmt.Fprintf(w, "%5d  %-*s  last %s\n       %s\n",
			g.Count, width, repoName(g.Repo), g.Last.In(loc).Format("2006-01-02 15:04"), clean(g.Reason)); err != nil {
			return err
		}
	}
	return nil
}

func repoName(repo string) string {
	if repo == "" {
		return "(no repo)"
	}
	return clean(repo)
}

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
