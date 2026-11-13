package policy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/op"
)

// RefUpdate is one command in a push.
type RefUpdate struct {
	Old, New, Ref string
}

const zeroOID = "0000000000000000000000000000000000000000"

func (u RefUpdate) Create() bool { return u.Old == zeroOID }
func (u RefUpdate) Delete() bool { return u.New == zeroOID }

// Branch returns the branch name, or "" for refs outside refs/heads/.
func (u RefUpdate) Branch() string {
	b, ok := strings.CutPrefix(u.Ref, "refs/heads/")
	if !ok {
		return ""
	}
	return b
}

// Push is the parsed command section of a receive-pack request.
type Push struct {
	Updates      []RefUpdate
	Capabilities []string
	// Raw is the bytes read for the command section, re-encoded from the
	// parse. The broker sends these, then the rest of the body unchanged.
	Raw []byte
	// Probe is set for the "0000" body git sends before a large push to
	// check that the server accepts it.
	Probe bool
	// Read is how many bytes of the body the command section took.
	Read int
}

// HasPack reports whether a pack follows the commands. git sends none when
// every update is a delete.
func (p Push) HasPack() bool {
	for _, u := range p.Updates {
		if !u.Delete() {
			return true
		}
	}
	return false
}

// SideBand reports whether the client asked for side-band output.
func (p Push) SideBand() bool {
	for _, c := range p.Capabilities {
		if c == "side-band-64k" || c == "side-band" {
			return true
		}
	}
	return false
}

// maxCommandSection bounds how much of a push body is read before the pack.
const maxCommandSection = 64 << 10

var allowedCaps = map[string]bool{
	"report-status": true, "report-status-v2": true, "side-band-64k": true,
	"side-band": true, "quiet": true, "atomic": true, "ofs-delta": true,
	"object-format=sha1": true, "delete-refs": true,
}

var hexOID = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ReadPush reads the command section of a receive-pack body from r, up to
// and including the first flush packet. The pack that follows stays unread
// in r.
func ReadPush(r *bufio.Reader) (Push, error) {
	var p Push
	read := 0
	first := true
	for {
		line, flush, n, err := readPkt(r)
		read += n
		if err != nil {
			return Push{}, err
		}
		if read > maxCommandSection {
			return Push{}, errorf("push command list is longer than %d bytes", maxCommandSection)
		}
		if flush {
			if first {
				p.Probe = true
			}
			break
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		if first {
			if bytes.HasPrefix(line, []byte("push-cert")) {
				return Push{}, errorf("hallpass doesn't forward signed pushes")
			}
			cmd, caps, ok := bytes.Cut(line, []byte{0})
			if !ok {
				return Push{}, errorf("push has no capability list")
			}
			line = cmd
			for c := range strings.FieldsSeq(string(caps)) {
				name, _, _ := strings.Cut(c, "=")
				if name == "agent" || name == "session-id" {
					p.Capabilities = append(p.Capabilities, c)
					continue
				}
				if name == "push-options" {
					return Push{}, errorf("hallpass doesn't forward push options")
				}
				if !allowedCaps[c] {
					return Push{}, errorf("push asks for capability %q, which hallpass doesn't forward", c)
				}
				p.Capabilities = append(p.Capabilities, c)
			}
		}
		first = false
		if bytes.HasPrefix(line, []byte("shallow ")) {
			return Push{}, errorf("hallpass doesn't forward shallow pushes")
		}
		if bytes.IndexByte(line, 0) >= 0 {
			return Push{}, errorf("malformed push command")
		}
		f := strings.Split(string(line), " ")
		if len(f) != 3 || !hexOID.MatchString(f[0]) || !hexOID.MatchString(f[1]) {
			return Push{}, errorf("malformed push command")
		}
		p.Updates = append(p.Updates, RefUpdate{Old: f[0], New: f[1], Ref: f[2]})
	}
	p.Read = read
	if !p.Probe {
		p.Raw = encodeCommands(p)
	} else {
		p.Raw = []byte("0000")
	}
	return p, nil
}

func encodeCommands(p Push) []byte {
	var b bytes.Buffer
	for i, u := range p.Updates {
		line := u.Old + " " + u.New + " " + u.Ref
		if i == 0 {
			line += "\x00" + strings.Join(p.Capabilities, " ")
		}
		writePkt(&b, line+"\n")
	}
	b.WriteString("0000")
	return b.Bytes()
}

// readPkt reads one pkt-line. It returns the payload, whether it was a
// flush packet, and the bytes consumed.
func readPkt(r *bufio.Reader) ([]byte, bool, int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, false, 0, errorf("truncated push")
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
	if err != nil {
		return nil, false, 4, errorf("malformed pkt-line length")
	}
	switch {
	case n == 0:
		return nil, true, 4, nil
	case n < 4 || n > 65520:
		return nil, false, 4, errorf("malformed pkt-line length")
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, false, 4, errorf("truncated push")
	}
	return buf, false, int(n), nil
}

func writePkt(w *bytes.Buffer, s string) {
	fmt.Fprintf(w, "%04x%s", len(s)+4, s)
}

// Branches is what the broker knows about a repo's branches when it checks
// a push.
type Branches struct {
	// Default is the default branch, or "" for an empty repo.
	Default string
	// Ops is what the repo's config lets agents do. With op.PushDefault
	// they may update the default branch, though not delete it, even when
	// a protected pattern names it. The first push to an empty repo, which
	// creates the default branch, passes without it.
	Ops       op.Set
	Protected []string // patterns: exact names or a trailing "/*"
	// Tip returns the commit this machine's agents last pushed to a branch
	// they created, or "" for any other branch. Agents may update or delete
	// a branch only from that commit.
	Tip func(branch string) string
	// Repo names the repo in refusal messages.
	Repo github.Repo
}

// CheckPush returns the reason each refused update was refused, keyed by
// ref. An empty map means every update may go upstream.
func CheckPush(p Push, b Branches) map[string]string {
	refused := map[string]string{}
	// GitHub makes one branch of an empty repo's first push the default.
	// checkUpdate lets that one past protected_branches, so a push that
	// creates more could get the rest past too.
	if b.Default == "" && len(p.Updates) > 1 {
		for _, u := range p.Updates {
			refused[u.Ref] = b.Repo.String() + " is empty, so push one branch first; it becomes the default branch"
		}
		return refused
	}
	seen := map[string]bool{}
	for _, u := range p.Updates {
		if seen[u.Ref] {
			// The ledger reads GitHub's answer by ref, so one ref must
			// mean one command.
			refused[u.Ref] = "push names " + u.Ref + " twice"
			continue
		}
		seen[u.Ref] = true
		if reason := checkUpdate(u, b); reason != "" {
			refused[u.Ref] = reason
		}
	}
	return refused
}

func checkUpdate(u RefUpdate, b Branches) string {
	branch := u.Branch()
	switch {
	case strings.HasPrefix(u.Ref, "refs/tags/"):
		return "agents can't push tags"
	case branch == "":
		return "agents can only push branches under refs/heads/"
	case !ValidBranch(branch):
		return "not a valid branch name"
	case u.Create() && u.Delete():
		return "malformed push command"
	case b.Default == "" && u.Create():
		// An empty repo has no default branch yet, and GitHub makes the
		// first branch pushed to it the default. That push needs no
		// op.PushDefault: the repo holds nothing for it to replace. It has
		// no refs to update or delete, so anything but a create goes on to
		// the checks below.
		return ""
	case strings.EqualFold(branch, b.Default):
		if err := CheckOps([]op.Op{op.PushDefault}, b.Ops, b.Repo); err != nil {
			return branch + " is the default branch; push another branch and open a PR. " + err.Error()
		}
		if u.Delete() {
			return "agents can't delete the default branch"
		}
		return ""
	case protected(branch, b.Protected):
		return branch + " is protected in hallpass's config"
	case u.Create():
		return ""
	}
	tip := ""
	if b.Tip != nil {
		tip = b.Tip(branch)
	}
	if tip != "" && tip == u.Old {
		return ""
	}
	verb := "update"
	if u.Delete() {
		verb = "delete"
	}
	why := "agents can only " + verb + " branches they created"
	if tip != "" {
		why = branch + " has changed since an agent last pushed it (agents pushed " + tip[:7] + ", this push starts from " + u.Old[:7] + ")"
	}
	return why + ". To let agents " + verb + " it as it is: sudo /opt/hallpass/bin/hallpass ledger add " + b.Repo.String() + " " + branch + " " + u.Old
}

func protected(branch string, patterns []string) bool {
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, "/*"); ok {
			if strings.HasPrefix(strings.ToLower(branch), strings.ToLower(prefix)+"/") {
				return true
			}
		} else if strings.EqualFold(branch, p) {
			return true
		}
	}
	return false
}

// ValidBranch applies git check-ref-format's rules to a branch name.
func ValidBranch(b string) bool {
	if b == "" || b == "@" || strings.HasPrefix(b, "/") || strings.HasSuffix(b, "/") ||
		strings.HasSuffix(b, ".") || strings.Contains(b, "..") || strings.Contains(b, "//") ||
		strings.Contains(b, "@{") || strings.HasPrefix(b, "-") {
		return false
	}
	for part := range strings.SplitSeq(b, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	for _, c := range b {
		if c < 0x20 || c == 0x7f || strings.ContainsRune(" ~^:?*[\\", c) {
			return false
		}
	}
	return true
}

// RefusePush builds the receive-pack response git expects when the broker
// refuses a push: "unpack ok" and an "ng" line per ref, in side-band when the
// client asked for it. git prints each as "! [remote rejected]".
func RefusePush(p Push, refused map[string]string) []byte {
	var status bytes.Buffer
	writePkt(&status, "unpack ok\n")
	for _, u := range p.Updates {
		reason, ok := refused[u.Ref]
		if !ok {
			reason = "another ref in this push was refused"
		}
		writePkt(&status, "ng "+u.Ref+" hallpass: "+reason+"\n")
	}
	status.WriteString("0000")
	if !p.SideBand() {
		return status.Bytes()
	}
	var out bytes.Buffer
	writePkt(&out, "\x01"+status.String())
	out.WriteString("0000")
	return out.Bytes()
}

// Report is GitHub's answer to a push: the refs it updated, and the ones
// it rejected, each with GitHub's reason.
type Report struct {
	Accepted []string
	Rejected []Rejection
}

// Rejection is a ref GitHub didn't update, and why. Both come from the
// network, so treat them as untrusted text.
type Rejection struct {
	Ref    string `json:"ref"`
	Reason string `json:"reason"`
}

// ReportStatus reads the ref results from GitHub's receive-pack response,
// which the broker relays to git unchanged: an "ok REF" line for each ref
// GitHub accepted and an "ng REF REASON" line for each it rejected. A
// response it can't parse yields neither, so nothing gets recorded.
func ReportStatus(body []byte, sideBand bool) Report {
	r := bufio.NewReader(bytes.NewReader(body))
	var status []byte
	if sideBand {
		for {
			line, flush, _, err := readPkt(r)
			if err != nil || flush {
				break
			}
			if len(line) > 0 && line[0] == 1 {
				status = append(status, line[1:]...)
			}
		}
		r = bufio.NewReader(bytes.NewReader(status))
	}
	var rep Report
	for {
		line, flush, _, err := readPkt(r)
		if err != nil || flush {
			break
		}
		l := strings.TrimSuffix(string(line), "\n")
		if ref, found := strings.CutPrefix(l, "ok "); found {
			rep.Accepted = append(rep.Accepted, ref)
		} else if rest, found := strings.CutPrefix(l, "ng "); found {
			ref, reason, _ := strings.Cut(rest, " ")
			rep.Rejected = append(rep.Rejected, Rejection{Ref: ref, Reason: reason})
		}
	}
	return rep
}

// Error is a refusal with a message for the client.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errorf(format string, args ...any) error {
	return &Error{Msg: fmt.Sprintf(format, args...)}
}

// IsRefusal reports whether err is a policy refusal, as opposed to a broker
// failure.
func IsRefusal(err error) bool {
	var e *Error
	return errors.As(err, &e)
}

// cleanTarget rejects request targets with encodings or segments that could
// make the broker and GitHub read different paths.
func cleanTarget(t string) error {
	if !strings.HasPrefix(t, "/") {
		return errorf("request target must be a path")
	}
	path, _, _ := strings.Cut(t, "?")
	for _, c := range t {
		if c < 0x21 || c > 0x7e || c == '\\' || c == ';' || c == '#' {
			return errorf("request target has a character hallpass doesn't accept")
		}
	}
	if strings.Contains(path, "%") || strings.Contains(path, "//") {
		return errorf("request target has an encoding hallpass doesn't accept")
	}
	for _, seg := range strings.Split(path, "/")[1:] {
		if seg == "." || seg == ".." {
			return errorf("request target has a dot segment")
		}
	}
	return nil
}
