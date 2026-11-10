package sshgate

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mbriggs/hallpass/internal/github"
)

// A fetch of a repo outside the allowlist goes to GitHub over smart HTTP
// with no credential at all, so GitHub answers it with only what anyone
// could fetch. git talks to the broker as it would to an SSH server. With
// protocol v2 that maps onto HTTP directly: the server sends its
// capabilities first, which is GET info/refs, and then each command the
// client sends, up to its flush packet, is one POST to git-upload-pack. The
// server keeps no state between commands, on SSH as on HTTP, so the client
// sends everything a command needs every time.
//
// The broker relays the bytes both ways without reading them. Whatever the
// client asks, GitHub decides what an anonymous client may see.

// DefaultGitURL is where the gate fetches without a credential.
const DefaultGitURL = "https://github.com"

// maxRedirects is how many redirects a fetch follows, as GitHub sends for a
// renamed or transferred public repo.
const maxRedirects = 3

// maxSession is the longest a fetch without a credential may take, on top
// of the idle cutoff, so a client trickling bytes can't hold one of the
// slots forever.
const maxSession = 2 * time.Hour

// anonTransport is the anonymous fetches' own HTTP transport. Nothing on it
// ever carries a credential.
var anonTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 2 * time.Minute,
	MaxIdleConns:          16,
	IdleConnTimeout:       90 * time.Second,
}

// anonClient follows no redirects itself: fetchAnonymous checks each one.
// It has no cookie jar, so no state carries from one request to the next.
var anonClient = &http.Client{
	Transport:     anonTransport,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// fetchAnonymous serves an upload-pack session for repo, which the
// allowlist doesn't cover, from GitHub's smart HTTP without a credential.
// why is the allowlist's refusal, which every refusal here ends with. It
// returns the repo GitHub served, which differs from repo after a
// redirect. An error is the refusal to send the client.
func (s *Server) fetchAnonymous(repo github.Repo, why string, in *bufio.Reader, out io.Writer, idle time.Duration) (github.Repo, error) {
	base, err := url.Parse(s.gitURL())
	if err != nil {
		return repo, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxSession)
	defer cancel()
	served, adv, err := s.advertise(ctx, base, repo, why, idle)
	if err != nil {
		return served, err
	}
	if _, err := out.Write(adv); err != nil {
		return served, err
	}
	endpoint := repoURL(base, served) + "/git-upload-pack"
	for !ended(in) {
		if err := command(ctx, endpoint, why, in, out, idle); err != nil {
			return served, err
		}
	}
	return served, nil
}

// ended reports whether git ended the session, which it does with a flush
// packet or by closing the stream.
func ended(in *bufio.Reader) bool {
	next, err := in.Peek(4)
	return err != nil || string(next) == "0000"
}

func (s *Server) gitURL() string {
	if s.GitURL != "" {
		return strings.TrimRight(s.GitURL, "/")
	}
	return DefaultGitURL
}

// repoURL is repo's smart HTTP URL under base. It's built from the parsed
// name, never from text GitHub or the client sent.
func repoURL(base *url.URL, repo github.Repo) string {
	return base.Scheme + "://" + base.Host + "/" + repo.Owner + "/" + repo.Name + ".git"
}

// advertise asks GitHub for repo's protocol v2 capabilities, following
// redirects only to another repo on the same host that the policy lets the
// gate fetch without a credential. It returns the repo it ended at and the
// capabilities as an SSH server would send them.
func (s *Server) advertise(ctx context.Context, base *url.URL, repo github.Repo, why string, idle time.Duration) (github.Repo, []byte, error) {
	for range maxRedirects + 1 {
		resp, err := send(ctx, http.MethodGet, repoURL(base, repo)+"/info/refs?service=git-upload-pack", nil, "", idle)
		if err != nil {
			return repo, nil, err
		}
		if resp.StatusCode/100 == 3 {
			resp.Body.Close()
			next, err := redirect(base, resp)
			if err != nil {
				return repo, nil, errors.New(err.Error() + " " + why)
			}
			if !s.Config.Anonymous(&next) {
				return next, nil, errors.New("GitHub redirected to " + next.String() + ", which the policy doesn't let hallpass fetch without a credential. " + why)
			}
			repo = next
			continue
		}
		adv, err := capabilities(resp, why)
		return repo, adv, err
	}
	return repo, nil, errors.New("GitHub redirected more than " + strconv.Itoa(maxRedirects) + " times. " + why)
}

func capabilities(resp *http.Response, why string) ([]byte, error) {
	defer resp.Body.Close()
	if err := answered(resp, "application/x-git-upload-pack-advertisement", why); err != nil {
		return nil, err
	}
	adv, err := readCapabilities(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("couldn't read GitHub's answer: %w", err)
	}
	return adv, nil
}

// redirect reads where a redirect from info/refs goes. It follows only to
// the same scheme and host, and only to another repo's info/refs.
func redirect(base *url.URL, resp *http.Response) (github.Repo, error) {
	loc, err := resp.Location()
	refuse := errors.New("GitHub redirected somewhere hallpass doesn't follow.")
	if err != nil || loc.Scheme != base.Scheme || !strings.EqualFold(loc.Host, base.Host) || loc.User != nil {
		return github.Repo{}, refuse
	}
	p, ok := strings.CutSuffix(loc.Path, "/info/refs")
	if !ok || loc.RawQuery != "service=git-upload-pack" {
		return github.Repo{}, refuse
	}
	repo, err := github.ParseRepo(p)
	if err != nil {
		return github.Repo{}, refuse
	}
	return repo, nil
}

// send makes a request with no credential, and cuts its answer off when
// nothing arrives for idle. A body is a command, of contentType.
func send(ctx context.Context, method, u string, body io.Reader, contentType string, idle time.Duration) (*http.Response, error) {
	ctx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		cancel()
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Accept", "application/x-git-upload-pack-result")
	}
	req.Header.Set("User-Agent", "git/hallpass")
	req.Header.Set("Git-Protocol", "version=2")
	resp, err := anonClient.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("couldn't reach GitHub: %w", err)
	}
	resp.Body = &idleBody{ReadCloser: resp.Body, t: time.AfterFunc(idle, cancel), idle: idle, cancel: cancel}
	return resp, nil
}

// answered checks that GitHub served the request: a 200 of git's smart
// protocol. Otherwise it says what GitHub answered.
func answered(resp *http.Response, contentType, why string) error {
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return errors.New("GitHub is limiting git without a token from this machine's address (" + resp.Status + "); try again later. " + why)
	case resp.StatusCode != http.StatusOK:
		return errors.New("Without a token, GitHub answered " + resp.Status + ". " + why)
	case resp.Header.Get("Content-Type") != contentType:
		return errors.New("Without a token, GitHub didn't answer with git's smart protocol. " + why)
	}
	return nil
}

// command sends the client's next command, up to its flush packet, to
// endpoint, and relays GitHub's answer. The request streams as the client
// sends it and the answer as GitHub sends it, so neither is held whole.
func command(ctx context.Context, endpoint, why string, in *bufio.Reader, out io.Writer, idle time.Duration) error {
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pw.CloseWithError(copyRequest(pw, in))
	}()
	// Whatever happens, stop the copy before in is read again: closing the
	// reader makes its next write fail. git sends a whole command before it
	// reads the answer, so the copy is done by the time the answer is.
	defer func() {
		_ = pr.Close()
		<-done
	}()
	resp, err := send(ctx, http.MethodPost, endpoint, pr, "application/x-git-upload-pack-request", idle)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := answered(resp, "application/x-git-upload-pack-result", why); err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("lost GitHub's answer: %w", err)
	}
	return nil
}

// copyRequest copies one protocol v2 command from r to w: pkt-lines up to
// and including the flush packet that ends it.
func copyRequest(w io.Writer, r io.Reader) error {
	buf := make([]byte, 65520)
	for {
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			return err
		}
		n, err := strconv.ParseUint(string(buf[:4]), 16, 16)
		switch {
		case err != nil || n == 2 || n == 3 || n > 65520:
			return errors.New("malformed pkt-line")
		case n < 4:
			// A flush (0000) ends the command; a delim (0001) splits it.
			if _, err := w.Write(buf[:4]); err != nil || n == 0 {
				return err
			}
			continue
		}
		if _, err := io.ReadFull(r, buf[4:n]); err != nil {
			return err
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return err
		}
	}
}

// readCapabilities reads GitHub's answer to info/refs for protocol v2: an
// optional "# service=git-upload-pack" line and its flush, then the
// capability list up to its flush. It returns the list as pkt-lines.
func readCapabilities(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)
	line, kind, err := pkt(br)
	if err != nil {
		return nil, err
	}
	if kind == data && strings.HasPrefix(string(line), "# service=") {
		if _, kind, err := pkt(br); err != nil || kind != flush {
			return nil, errors.New("malformed service line")
		}
		if line, kind, err = pkt(br); err != nil {
			return nil, err
		}
	}
	if kind != data || string(line) != "version 2\n" {
		return nil, errors.New("GitHub didn't offer git protocol v2")
	}
	var adv bytes.Buffer
	for {
		fmt.Fprintf(&adv, "%04x", len(line)+4)
		adv.Write(line)
		if line, kind, err = pkt(br); err != nil {
			return nil, err
		}
		switch kind {
		case flush:
			adv.WriteString("0000")
			return adv.Bytes(), nil
		case delim:
			return nil, errors.New("malformed capability list")
		}
	}
}

// idleBody cancels its request when a read waits longer than idle.
type idleBody struct {
	io.ReadCloser
	t      *time.Timer
	idle   time.Duration
	cancel context.CancelFunc
}

func (b *idleBody) Read(p []byte) (int, error) {
	b.t.Reset(b.idle)
	n, err := b.ReadCloser.Read(p)
	return n, err
}

func (b *idleBody) Close() error {
	b.t.Stop()
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// wantsV2 reports whether the client asked for protocol v2. GIT_PROTOCOL is
// colon-separated keys, of which git sets version=2.
func wantsV2(gitProtocol string) bool {
	for kv := range strings.SplitSeq(gitProtocol, ":") {
		if kv == "version=2" {
			return true
		}
	}
	return false
}
