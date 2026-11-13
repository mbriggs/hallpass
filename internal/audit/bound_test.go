package audit

import (
	"bytes"
	"log/slog"
	"strconv"
	"strings"
	"testing"
)

// journald splits a line past this many bytes into two entries.
const journalLineMax = 48 << 10

func boundedLine(t *testing.T, attrs ...any) string {
	t.Helper()
	var out bytes.Buffer
	log := slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{ReplaceAttr: BoundAttr}))
	log.With("via", "gh", "uid", 501).Warn("refused", attrs...)
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("logged %d lines", strings.Count(out.String(), "\n"))
	}
	return out.String()
}

// A record stays one line the log's readers take whole, whatever a client
// puts in the values it controls.
func TestBoundAttrKeepsALineShort(t *testing.T) {
	// Each of these is the costliest kind of text to quote.
	hostile := []string{
		strings.Repeat("x y", 40000),
		strings.Repeat("\x00", 100000),
		strings.Repeat("\xff", 100000),
		strings.Repeat("\u0085", 50000),
		strings.Repeat(`"\`, 50000),
		strings.Repeat("é ", 50000),
		// A second record, for a reader that took the line in two.
		strings.Repeat("a", 49000) + ` level=INFO msg=pushed via=ssh uid=0 repo=acme/widgets refs=[refs/heads/main]`,
	}
	var attrs []any
	for i := range 18 {
		attrs = append(attrs, "k"+strconv.Itoa(i), hostile[i%len(hostile)])
	}
	line := boundedLine(t, attrs...)
	if len(line) > journalLineMax {
		t.Fatalf("the line is %d bytes, past journald's %d", len(line), journalLineMax)
	}
	rec, ok := Parse(strings.TrimSuffix(line, "\n"))
	if !ok || rec.Msg != "refused" || rec.Get("via") != "gh" {
		t.Fatalf("the line doesn't parse as the record logged: %v %+v", ok, rec)
	}
	for i := range 18 {
		v := rec.Get("k" + strconv.Itoa(i))
		if !strings.HasPrefix(hostile[i%len(hostile)], v[:strings.LastIndex(v, "...(")]) || !strings.HasSuffix(v, " more bytes)") {
			t.Errorf("k%d isn't a marked prefix of its value: %.60q...", i, v)
		}
	}
}

func TestBoundAttr(t *testing.T) {
	// Values under the bound, and kinds that are always short, are logged
	// as they were.
	refs := map[string]string{"refs/heads/a": "agents can't push tags"}
	line := boundedLine(t, "reason", "a short reason", "refs", refs, "sent", []string{"a", "b"}, "status", 404, "ok", true)
	for _, want := range []string{`reason="a short reason"`, `refs="map[refs/heads/a:agents can't push tags]"`, `sent="[a b]"`, "status=404", "ok=true"} {
		if !strings.Contains(line, want) {
			t.Errorf("no %s in %s", want, line)
		}
	}
	// A value just under the bound is whole, and one over it is cut on a
	// rune boundary and says how much is gone.
	whole := strings.Repeat("a", MaxAttr-2) // no quotes needed
	if line := boundedLine(t, "k", whole); !strings.Contains(line, "k="+whole+"\n") {
		t.Errorf("a value of %d bytes was cut", len(whole))
	}
	long := strings.Repeat("é", MaxAttr)
	rec, _ := Parse(strings.TrimSuffix(boundedLine(t, "k", long), "\n"))
	v := rec.Get("k")
	kept, note, _ := strings.Cut(v, "...(")
	if kept == "" || strings.Trim(kept, "é") != "" {
		t.Errorf("cut inside a rune: %q", v[max(0, len(kept)-8):])
	}
	if want := strconv.Itoa(len(long)-len(kept)) + " more bytes)"; note != want {
		t.Errorf("note %q, want %q", note, want)
	}
	// A slice or a map past the bound is cut as its text.
	many := map[string]string{}
	for i := range 500 {
		many["refs/heads/agent/"+strconv.Itoa(i)] = "agents can only update branches they created"
	}
	if line := boundedLine(t, "refs", many); len(line) > MaxAttr+200 || !strings.Contains(line, "more bytes)") {
		t.Errorf("a long map wasn't cut: %d bytes", len(line))
	}
}
