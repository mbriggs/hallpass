package audit

import (
	"fmt"
	"log/slog"
	"strconv"
	"unicode/utf8"
)

// MaxAttr is the most bytes one attr's value takes in a log line, quotes
// and escapes included.
//
// A client decides how long some values are: a refusal's reason quotes the
// path and query it sent, and its process chain and refs are its own. The
// log's readers take a record to be one line. journald splits a line longer
// than 48K into two entries, and hallpass log reads them as two lines, so a
// long enough value would end its record early and start another with text
// the client chose. Scan also skips a line past 1 MiB, which would drop the
// record. A line holds under twenty attrs, so at this bound it stays under
// 48K whatever they hold.
const MaxAttr = 2048

// markRoom is kept free for the note a cut value ends with.
const markRoom = 40

// BoundAttr is the broker logger's ReplaceAttr. It cuts a value that would
// take more than MaxAttr bytes in the line and says how much it left out.
// Numbers, times, and the like are short and pass as they are.
func BoundAttr(_ []string, a slog.Attr) slog.Attr {
	var s string
	switch a.Value.Kind() {
	case slog.KindString:
		s = a.Value.String()
	case slog.KindAny:
		// As the text handler prints a slice or a map.
		s = fmt.Sprintf("%+v", a.Value.Any())
	default:
		return a
	}
	// Quoting makes a byte at most four.
	if len(s)*4+2 <= MaxAttr || len(strconv.Quote(s)) <= MaxAttr {
		return a
	}
	n, room := 0, MaxAttr-2-markRoom
	for n < len(s) {
		r, size := utf8.DecodeRuneInString(s[n:])
		// A byte that isn't UTF-8 is quoted as \xNN.
		cost := 4
		if r != utf8.RuneError || size > 1 {
			cost = len(strconv.Quote(s[n:n+size])) - 2
		}
		if cost > room {
			break
		}
		room -= cost
		n += size
	}
	return slog.String(a.Key, s[:n]+fmt.Sprintf("...(%d more bytes)", len(s)-n))
}
