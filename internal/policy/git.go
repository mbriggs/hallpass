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
)

// GitService is the smart-HTTP endpoint a git request is for.
type GitService int

const (
	GitInfoRefsUpload GitService = iota + 1
	GitInfoRefsReceive
	GitUploadPack
	GitReceivePack
)

func (s GitService) String() string {
	switch s {
	case GitInfoRefsUpload:
		return "info/refs upload-pack"
	case GitInfoRefsReceive:
		return "info/refs receive-pack"
	case GitUploadPack:
		return "upload-pack"
	case GitReceivePack:
		return "receive-pack"
	}
	return "unknown"
}

// GitRequest is a git smart-HTTP request the broker may forward.
type GitRequest struct {
	Repo    github.Repo
	Service GitService
}

// UpstreamPath is the path the broker sends to github.com, rebuilt from the
// parsed parts rather than copied from the client.
func (g GitRequest) UpstreamPath() string {
	base := "/" + g.Repo.Owner + "/" + g.Repo.Name + ".git/"
	switch g.Service {
	case GitInfoRefsUpload:
		return base + "info/refs?service=git-upload-pack"
	case GitInfoRefsReceive:
		return base + "info/refs?service=git-receive-pack"
	case GitUploadPack:
		return base + "git-upload-pack"
	default:
		return base + "git-receive-pack"
	}
}

// Write reports whether the request can change the repo.
func (g GitRequest) Write() bool {
	return g.Service == GitInfoRefsReceive || g.Service == GitReceivePack
}

var gitPath = regexp.MustCompile(`^/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})/(info/refs|git-upload-pack|git-receive-pack)$`)

// ParseGit classifies a request on the git socket. target is the raw request
// target (path and query) exactly as the client sent it.
func ParseGit(method, target, contentType string) (GitRequest, error) {
	if err := cleanTarget(target); err != nil {
		return GitRequest{}, err
	}
	path, query, _ := strings.Cut(target, "?")
	m := gitPath.FindStringSubmatch(path)
	if m == nil {
		return GitRequest{}, errorf("hallpass only forwards git fetch and push, not %s", path)
	}
	name := m[2]
	if strings.HasSuffix(name, ".git") {
		name = strings.TrimSuffix(name, ".git")
	}
	repo, err := github.ParseRepo(m[1] + "/" + name)
	if err != nil {
		return GitRequest{}, errorf("%v", err)
	}
	g := GitRequest{Repo: repo}
	switch m[3] {
	case "info/refs":
		if method != "GET" {
			return GitRequest{}, errorf("info/refs must be GET")
		}
		switch query {
		case "service=git-upload-pack":
			g.Service = GitInfoRefsUpload
		case "service=git-receive-pack":
			g.Service = GitInfoRefsReceive
		default:
			return GitRequest{}, errorf("hallpass doesn't support dumb HTTP git")
		}
	case "git-upload-pack":
		if method != "POST" || query != "" || contentType != "application/x-git-upload-pack-request" {
			return GitRequest{}, errorf("malformed upload-pack request")
		}
		g.Service = GitUploadPack
	case "git-receive-pack":
		if method != "POST" || query != "" || contentType != "application/x-git-receive-pack-request" {
			return GitRequest{}, errorf("malformed receive-pack request")
		}
		g.Service = GitReceivePack
	}
	return g, nil
}

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
			for _, c := range strings.Fields(string(caps)) {
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
	Default string
	// PushDefault lets agents create or update the default branch, though
	// not delete it, even when a protected pattern names it.
	PushDefault bool
	Protected   []string // patterns: exact names or a trailing "/*"
	// Ours reports whether this machine's agents created the branch.
	Ours func(branch string) bool
}

// CheckPush returns the reason each refused update was refused, keyed by
// ref. An empty map means every update may go upstream.
func CheckPush(p Push, b Branches) map[string]string {
	refused := map[string]string{}
	for _, u := range p.Updates {
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
	case !validBranch(branch):
		return "not a valid branch name"
	case u.Create() && u.Delete():
		return "malformed push command"
	case strings.EqualFold(branch, b.Default) && !b.PushDefault:
		return branch + " is the default branch; push another branch and open a PR"
	case strings.EqualFold(branch, b.Default) && u.Delete():
		return "agents can't delete the default branch"
	case strings.EqualFold(branch, b.Default):
		return ""
	case protected(branch, b.Protected):
		return branch + " is protected in hallpass's config"
	case u.Create():
		return ""
	case b.Ours == nil || !b.Ours(branch):
		if u.Delete() {
			return "agents can only delete branches they created"
		}
		return "agents can only update branches they created; run sudo /opt/hallpass/bin/hallpass ledger add to allow this one"
	}
	return ""
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

// validBranch applies git check-ref-format's rules to a branch name.
func validBranch(b string) bool {
	if b == "" || b == "@" || strings.HasPrefix(b, "/") || strings.HasSuffix(b, "/") ||
		strings.HasSuffix(b, ".") || strings.Contains(b, "..") || strings.Contains(b, "//") ||
		strings.Contains(b, "@{") || strings.HasPrefix(b, "-") {
		return false
	}
	for _, part := range strings.Split(b, "/") {
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

// ReportStatus reads the ref results from GitHub's receive-pack response,
// which the broker relays to git unchanged. It returns the refs GitHub
// accepted. A response it can't parse yields none, so nothing gets recorded.
func ReportStatus(body []byte, sideBand bool) []string {
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
	var ok []string
	for {
		line, flush, _, err := readPkt(r)
		if err != nil || flush {
			break
		}
		if ref, found := strings.CutPrefix(strings.TrimSuffix(string(line), "\n"), "ok "); found {
			ok = append(ok, ref)
		}
	}
	return ok
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
