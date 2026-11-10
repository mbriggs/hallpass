// Package audit reads the broker's log: the lines slog's TextHandler writes
// for each request the broker allows or refuses. It parses them, filters
// them, and renders them for a terminal. Where the lines come from, the
// journal or a file, is the caller's business.
//
// Clients choose much of what the log holds: the process chain, repo names,
// routes, and the text of many refusals. TextHandler quotes any value with a
// control character, so the log itself is safe to print, but parsing undoes
// the quoting. Everything this package renders goes through clean first.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Record is one line of the log.
type Record struct {
	Time  time.Time
	Level string
	Msg   string
	// Attrs are the line's other key=value pairs, in the order logged.
	Attrs []Attr
}

// Attr is one key=value pair, unquoted.
type Attr struct{ Key, Value string }

// Get returns the value of the first attr named key, or "".
func (r Record) Get(key string) string {
	for _, a := range r.Attrs {
		if a.Key == key {
			return a.Value
		}
	}
	return ""
}

// Repos lists the repos the request names: the repo attr, split on its
// commas, and after a rename, the name GitHub has now.
func (r Record) Repos() []string {
	var out []string
	if repo := r.Get("repo"); repo != "" {
		out = strings.Split(repo, ",")
	}
	if now := r.Get("now"); now != "" {
		out = append(out, now)
	}
	return out
}

// Refused reports whether the broker refused the request.
func (r Record) Refused() bool { return r.Msg == "refused" }

// Refusal is one reason a request was refused. A push refusal has one per
// refused ref, since each ref can fail for its own reason.
type Refusal struct {
	Ref    string `json:"ref"`
	Reason string `json:"reason"`
}

// Refusals splits a refused record into its reasons. It returns nil for a
// record that isn't a refusal.
func (r Record) Refusals() []Refusal {
	if !r.Refused() {
		return nil
	}
	reason := r.Get("reason")
	if reason == "push" {
		if refs := parseRefMap(r.Get("refs")); len(refs) > 0 {
			return refs
		}
	}
	return []Refusal{{Reason: reason}}
}

// Rejected reads the refs GitHub rejected in a push the broker forwarded:
// the rejected attr, JSON written by the SSH gate, and rejected_more, how
// many past those it left out. ok is false when rejected is there but isn't
// that JSON. A record without the attr, which includes every push line
// from before the broker logged it, has none.
func (r Record) Rejected() (refs []Refusal, more int, ok bool) {
	raw := r.Get("rejected")
	if raw == "" {
		return nil, 0, true
	}
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return nil, 0, false
	}
	more, _ = strconv.Atoi(r.Get("rejected_more"))
	return refs, max(more, 0), true
}

// refStart finds where each entry starts in the fmt rendering of a
// map[string]string of refs, "map[refs/heads/a:why refs/heads/b:why]". A ref
// name can't hold a space or a colon, so " refs/...:" only starts an entry.
var refStart = regexp.MustCompile(`(?:^| )(refs/[^ :]+):`)

// parseRefMap reads the refs attr of a refused push. It returns nil if refs
// isn't in that form.
func parseRefMap(refs string) []Refusal {
	body, ok := strings.CutPrefix(refs, "map[")
	if !ok {
		return nil
	}
	body, ok = strings.CutSuffix(body, "]")
	if !ok {
		return nil
	}
	locs := refStart.FindAllStringSubmatchIndex(body, -1)
	if len(locs) == 0 || locs[0][0] != 0 {
		return nil
	}
	var out []Refusal
	for i, l := range locs {
		end := len(body)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out = append(out, Refusal{Ref: body[l[2]:l[3]], Reason: body[l[1]:end]})
	}
	return out
}

// Parse reads one line slog's TextHandler wrote. It reports false for a line
// that isn't one, such as systemd's own lines in the journal or a panic's
// stack trace.
func Parse(line string) (Record, bool) {
	var r Record
	var haveTime, haveMsg bool
	s := strings.TrimRight(line, "\r\n")
	for {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			break
		}
		key, rest, ok := token(s, true)
		if !ok || !strings.HasPrefix(rest, "=") {
			return Record{}, false
		}
		val, rest, ok := token(rest[1:], false)
		if !ok {
			return Record{}, false
		}
		s = rest
		switch {
		case key == "time" && !haveTime:
			t, err := time.Parse(time.RFC3339Nano, val)
			if err != nil {
				return Record{}, false
			}
			r.Time, haveTime = t, true
		case key == "level" && r.Level == "":
			r.Level = val
		case key == "msg" && !haveMsg:
			r.Msg, haveMsg = val, true
		default:
			r.Attrs = append(r.Attrs, Attr{key, val})
		}
	}
	if !haveTime || !haveMsg || r.Level == "" {
		return Record{}, false
	}
	return r, true
}

// token reads a key (up to '=') or a value (up to ' '), either of which
// TextHandler quotes with strconv.Quote when it has to.
func token(s string, key bool) (tok, rest string, ok bool) {
	if strings.HasPrefix(s, `"`) {
		q, err := strconv.QuotedPrefix(s)
		if err != nil {
			return "", "", false
		}
		tok, err = strconv.Unquote(q)
		return tok, s[len(q):], err == nil
	}
	stop := " "
	if key {
		stop = "= "
	}
	i := strings.IndexAny(s, stop)
	if i < 0 {
		i = len(s)
	}
	if key && i == 0 {
		return "", "", false
	}
	if key && (i == len(s) || s[i] != '=') {
		return "", "", false
	}
	return s[:i], s[i:], true
}

// Filter picks records. The zero Filter picks every record.
type Filter struct {
	// Refused keeps only refusals.
	Refused bool
	// Repo keeps only requests for this OWNER/NAME, matched without regard
	// to case against the name the client asked for and, after a rename,
	// the current one. A GraphQL request that touches several repos logs
	// them all, joined by commas, and matches any of them.
	Repo string
	// Since keeps only records at or after it, when set.
	Since time.Time
}

// Match reports whether f picks r.
func (f Filter) Match(r Record) bool {
	if f.Refused && !r.Refused() {
		return false
	}
	if f.Repo != "" && !slices.ContainsFunc(r.Repos(), func(repo string) bool { return strings.EqualFold(repo, f.Repo) }) {
		return false
	}
	return f.Since.IsZero() || !r.Time.Before(f.Since)
}

// maxLine is the longest line Scan reads. The broker's lines are a few
// hundred bytes; anything far longer isn't one of its records.
const maxLine = 1 << 20

// Scan calls fn for each record in r that f picks, in order. It returns how
// many lines it read in all, so a caller can tell an empty log from one it
// couldn't parse.
func Scan(r io.Reader, f Filter, fn func(Record)) (lines int, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br)
		if errors.Is(err, io.EOF) {
			return lines, nil
		}
		if err != nil {
			return lines, err
		}
		lines++
		if rec, ok := Parse(line); ok && f.Match(rec) {
			fn(rec)
		}
	}
}

// readLine returns the next line, or "" for one longer than maxLine, whose
// rest it skips.
func readLine(br *bufio.Reader) (string, error) {
	var b []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(b) <= maxLine {
			b = append(b, chunk...)
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(b) > 0:
			err = nil
		}
		if len(b) > maxLine {
			b = nil
		}
		return string(b), err
	}
}

// ParseSince reads a --since value: a duration back from now such as 90m,
// 2h, or 3d, a date such as 2026-11-01 (midnight, local time), a date and
// time such as "2026-11-01 14:00", or an RFC 3339 time.
func ParseSince(s string, now time.Time) (time.Time, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n >= 0 {
			return now.AddDate(0, 0, -n), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	for _, layout := range []string{"2006-01-02", "2006-01-02 15:04", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, now.Location()); err == nil {
			return t, nil
		}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, errors.New("--since takes a duration like 2h or 3d, a date like 2026-11-01, or a time like \"2026-11-01 14:00\"")
}
