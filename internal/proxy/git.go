package proxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	"github.com/mbriggs/hallpass/internal/op"
	"github.com/mbriggs/hallpass/internal/policy"
)

// maxReport bounds how much of GitHub's push response the broker keeps to
// read which refs it accepted. The response streams to git regardless.
const maxReport = 1 << 20

func (s *Server) serveGit(w http.ResponseWriter, r *http.Request) {
	p := peerFrom(r.Context())
	log := s.Log.With("via", "git", "uid", p.UID, "pid", p.PID, "procs", p.Procs)
	refuse := func(status int, msg string, attrs ...any) {
		log.Warn("refused", append([]any{"reason", msg}, attrs...)...)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		io.WriteString(w, "hallpass: "+msg+"\n")
	}

	if h := strings.TrimSuffix(r.Host, ":80"); h != "github.com" {
		refuse(http.StatusMisdirectedRequest, "hallpass only serves github.com")
		return
	}
	g, err := policy.ParseGit(r.Method, r.RequestURI, r.Header.Get("Content-Type"))
	if err != nil {
		refuse(http.StatusForbidden, err.Error())
		return
	}
	log = log.With("repo", g.Repo.String(), "op", g.Service.String())
	rule, ok := s.Config.Allowed(g.Repo)
	switch {
	case !ok:
		refuse(http.StatusForbidden, g.Repo.String()+" isn't in hallpass's allowlist. To allow it: sudo /opt/hallpass/bin/hallpass allow "+g.Repo.String())
		return
	case g.Write() && !rule.Write:
		refuse(http.StatusForbidden, "agents may only read "+g.Repo.String())
		return
	case rule.Via != "https":
		refuse(http.StatusForbidden, g.Repo.String()+" goes through hallpass over SSH, not HTTPS")
		return
	case s.Token == "":
		refuse(http.StatusServiceUnavailable, "this machine has no GitHub token. Get one: sudo /opt/hallpass/bin/hallpass login")
		return
	}

	body := io.Reader(http.NoBody)
	var push policy.Push
	if r.Method == "POST" {
		body = io.LimitReader(r.Body, 4<<30)
	}
	if g.Service == policy.GitReceivePack {
		if r.Header.Get("Content-Encoding") != "" {
			refuse(http.StatusUnsupportedMediaType, "git doesn't compress pushes, so hallpass doesn't accept compressed ones")
			return
		}
		br := bufio.NewReader(r.Body)
		push, err = policy.ReadPush(br)
		if err != nil {
			refuse(http.StatusForbidden, err.Error())
			return
		}
		if push.Probe {
			// git's probe is "0000" and nothing else. Anything after it
			// would reach GitHub unchecked.
			if _, err := br.ReadByte(); err != io.EOF {
				refuse(http.StatusForbidden, "malformed push probe")
				return
			}
		} else {
			def, err := s.defaultBranch(r.Context(), g.Repo)
			if err != nil {
				refuse(http.StatusBadGateway, "couldn't check the default branch: "+err.Error())
				return
			}
			refused := policy.CheckPush(push, policy.Branches{
				Default:     def,
				PushDefault: rule.Ops.Has(op.PushDefault),
				Protected:   s.Config.ProtectedBranches,
				Ours:        func(b string) bool { return s.Ledger.Has(g.Repo, b) },
			})
			if len(refused) > 0 {
				log.Warn("refused", "reason", "push", "refs", refused)
				// git sends the whole pack before it reads the answer, so
				// take it, or git sees a broken pipe instead of the reasons.
				io.Copy(io.Discard, io.LimitReader(br, 1<<30))
				w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
				w.Write(policy.RefusePush(push, refused))
				return
			}
		}
		body = io.MultiReader(bytes.NewReader(push.Raw), br)
	}

	up, err := http.NewRequestWithContext(r.Context(), r.Method, s.Config.Git()+g.UpstreamPath(), body)
	if err != nil {
		refuse(http.StatusInternalServerError, err.Error())
		return
	}
	copyHeaders(up.Header, r.Header, "Accept", "Accept-Encoding", "Content-Type", "User-Agent")
	if g.Service != policy.GitReceivePack {
		copyHeaders(up.Header, r.Header, "Content-Encoding", "Git-Protocol")
	}
	switch {
	case r.ContentLength > 0 && g.Service == policy.GitReceivePack:
		up.ContentLength = r.ContentLength - int64(push.Read) + int64(len(push.Raw))
	case r.ContentLength > 0:
		up.ContentLength = r.ContentLength
	}
	up.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+s.Token)))

	resp, err := s.upstream().Do(up)
	if err != nil {
		refuse(http.StatusBadGateway, "couldn't reach GitHub: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if msg := upstreamProblem(resp); msg != "" {
		refuse(http.StatusForbidden, msg)
		return
	}
	copyHeaders(w.Header(), resp.Header, "Content-Type", "Content-Encoding", "Cache-Control", "Expires", "Pragma")
	w.WriteHeader(resp.StatusCode)

	var report bytes.Buffer
	out := io.Writer(w)
	if g.Service == policy.GitReceivePack && !push.Probe {
		out = io.MultiWriter(w, &capped{buf: &report, max: maxReport})
	}
	flushCopy(w, out, resp.Body)

	attrs := []any{"status", resp.StatusCode}
	if g.Service == policy.GitReceivePack && !push.Probe {
		accepted := policy.ReportStatus(report.Bytes(), push.SideBand())
		for _, ref := range accepted {
			for _, u := range push.Updates {
				if u.Ref == ref && u.Create() {
					if err := s.Ledger.Add(g.Repo, u.Branch(), p.Procs); err != nil {
						log.Error("ledger write failed; agents can't update this branch later", "branch", u.Branch(), "err", err)
					}
				}
			}
		}
		attrs = append(attrs, "pushed", accepted)
	}
	log.Info("allowed", attrs...)
}

// flushCopy streams src to dst, flushing as it goes so git sees progress
// while GitHub works.
func flushCopy(w http.ResponseWriter, dst io.Writer, src io.Reader) {
	f, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if f != nil {
				f.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

type capped struct {
	buf *bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
