package sshgate

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"unicode/utf8"

	"github.com/mbriggs/hallpass/internal/policy"
)

// Bounds on what one push's log line says about the refs GitHub rejected.
// Past maxRejected refs, rejected_more counts the rest.
const (
	maxRejected   = 20
	maxRejectRef  = 256
	maxRejectWhy  = 300
	truncatedMark = "..."
)

// logReport logs GitHub's answer to a push the broker forwarded:
//
//	level=INFO msg=pushed refs=[refs/heads/a]
//	level=WARN msg=pushed refs=[refs/heads/a] rejected="[{\"ref\":\"refs/heads/b\",\"reason\":\"non-fast-forward\"}]"
//	level=WARN msg=rejected refs=[] rejected="[...]" rejected_more=3
//
// refs keeps the form it always had, the accepted refs as fmt prints a
// []string, which works because a ref name can't hold a space. GitHub's
// reasons can hold anything, so rejected is JSON, which hallpass log
// decodes. A push GitHub rejected in part is still pushed; one it rejected
// whole is rejected. Neither is a hallpass refusal, so neither is msg
// refused, which log --refused and --summary count.
func logReport(log *slog.Logger, rep policy.Report) {
	attrs := []any{"refs", rep.Accepted}
	if len(rep.Rejected) == 0 {
		log.Info("pushed", attrs...)
		return
	}
	shown := rep.Rejected[:min(len(rep.Rejected), maxRejected)]
	list := make([]policy.Rejection, len(shown))
	for i, r := range shown {
		list[i] = policy.Rejection{Ref: truncate(r.Ref, maxRejectRef), Reason: truncate(r.Reason, maxRejectWhy)}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(list)
	attrs = append(attrs, "rejected", string(bytes.TrimSuffix(b.Bytes(), []byte("\n"))))
	if more := len(rep.Rejected) - len(shown); more > 0 {
		attrs = append(attrs, "rejected_more", more)
	}
	msg := "pushed"
	if len(rep.Accepted) == 0 {
		msg = "rejected"
	}
	log.Warn(msg, attrs...)
}

// sent is what the forwarded line says of a push: each command as
// REF:OLD..NEW, up to maxRejected of them, and sent_more for the rest. A
// ref here passed CheckPush, so it holds no space or colon.
//
//	level=INFO msg=forwarded sent=[refs/heads/a:0000...0000..1111...1111]
func sent(p policy.Push) []any {
	shown := p.Updates[:min(len(p.Updates), maxRejected)]
	list := make([]string, len(shown))
	for i, u := range shown {
		list[i] = truncate(u.Ref, maxRejectRef) + ":" + u.Old + ".." + u.New
	}
	attrs := []any{"sent", list}
	if more := len(p.Updates) - len(shown); more > 0 {
		attrs = append(attrs, "sent_more", more)
	}
	return attrs
}

// truncate cuts s to at most n bytes on a rune boundary, marking the cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - len(truncatedMark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncatedMark
}
