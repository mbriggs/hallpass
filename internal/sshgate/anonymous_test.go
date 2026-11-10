package sshgate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/peer"
)

// A redirect is followed only to another repo's info/refs on the same
// scheme and host, so a fetch never leaves GitHub.
func TestRedirectStaysOnGitHub(t *testing.T) {
	base, _ := url.Parse("https://github.com")
	for loc, want := range map[string]string{
		"https://github.com/octo/new.git/info/refs?service=git-upload-pack":              "octo/new",
		"/octo/new.git/info/refs?service=git-upload-pack":                                "octo/new",
		"https://GitHub.com/octo/new/info/refs?service=git-upload-pack":                  "octo/new",
		"https://evil.example/octo/new.git/info/refs?service=git-upload-pack":            "",
		"https://github.com.evil.example/octo/new.git/info/refs?service=git-upload-pack": "",
		"https://github.com@evil.example/octo/new.git/info/refs?service=git-upload-pack": "",
		"https://x@github.com/octo/new.git/info/refs?service=git-upload-pack":            "",
		"http://github.com/octo/new.git/info/refs?service=git-upload-pack":               "",
		"https://github.com:8443/octo/new.git/info/refs?service=git-upload-pack":         "",
		"https://github.com/octo/new.git/info/refs?service=git-receive-pack":             "",
		"https://github.com/octo/new.git/info/refs":                                      "",
		"https://github.com/login?return_to=/octo/new":                                   "",
		"https://github.com/a/b/c/info/refs?service=git-upload-pack":                     "",
		"https://github.com/../x/info/refs?service=git-upload-pack":                      "",
		"//evil.example/octo/new.git/info/refs?service=git-upload-pack":                  "",
	} {
		resp := &http.Response{StatusCode: http.StatusMovedPermanently, Header: http.Header{"Location": {loc}}, Request: &http.Request{URL: &url.URL{Scheme: "https", Host: "github.com", Path: "/octo/old.git/info/refs"}}}
		repo, err := redirect(base, resp)
		switch {
		case want == "" && err == nil:
			t.Errorf("%s: followed to %s", loc, repo)
		case want != "" && (err != nil || repo.String() != want):
			t.Errorf("%s: got %s, %v; want %s", loc, repo, err, want)
		}
	}
}

// Anonymous fetches get their own cap within the gate's connections, so
// they can't take every slot from the allowlist's repos.
func TestAnonymousFetchesHaveTheirOwnCap(t *testing.T) {
	release := make(chan struct{})
	gh := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer gh.Close()
	defer close(release)
	sock := socketPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{
		Config:    &config.Config{},
		Log:       slog.New(slog.DiscardHandler),
		Permitted: func(peer.Peer) bool { return true },
		GitURL:    gh.URL,
		limits:    limits{conns: 4, anonymous: 1},
	}
	go s.Serve(ln)
	fetch := func() net.Conn {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		hdr, _ := json.Marshal(Header{Service: "git-upload-pack", Repo: "octo/public", GitProtocol: "version=2"})
		c.Write(append(hdr, '\n'))
		return c
	}
	fetch() // holds the one anonymous slot, waiting on GitHub
	time.Sleep(100 * time.Millisecond)
	if got := stderr(t, fetch()); !strings.Contains(got, "too many fetches without a credential") {
		t.Errorf("second anonymous fetch got %q", got)
	}
}

func TestCopyRequestStopsAtFlush(t *testing.T) {
	req := "0014command=ls-refs\n00010009peel\n0000"
	in := bufio.NewReader(strings.NewReader(req + "0013command=fetch\n0000"))
	var out bytes.Buffer
	if err := copyRequest(&out, in); err != nil || out.String() != req {
		t.Fatalf("copyRequest = %q, %v; want %q", out.String(), err, req)
	}
	if rest, _ := in.Peek(4); string(rest) != "0013" {
		t.Errorf("left %q for the next command", rest)
	}
	for _, bad := range []string{"0002", "0003", "zzzz", "0005", "fff1x"} {
		if err := copyRequest(&bytes.Buffer{}, strings.NewReader(bad)); err == nil {
			t.Errorf("copyRequest took %q", bad)
		}
	}
}

func TestReadCapabilities(t *testing.T) {
	caps := "000eversion 2\n0013ls-refs=unborn\n0000"
	for _, in := range []string{caps, "001e# service=git-upload-pack\n0000" + caps} {
		got, err := readCapabilities(strings.NewReader(in))
		if err != nil || string(got) != caps {
			t.Errorf("readCapabilities(%q) = %q, %v", in, got, err)
		}
	}
	// A v0 ref list isn't v2, and is refused rather than relayed.
	v0 := "001e# service=git-upload-pack\n0000003f" + strings.Repeat("a", 40) + " refs/heads/main\x00\n0000"
	if _, err := readCapabilities(strings.NewReader(v0)); err == nil {
		t.Error("readCapabilities took a v0 ref list")
	}
}

func FuzzCopyRequest(f *testing.F) {
	f.Add([]byte("0014command=ls-refs\n00010009peel\n0000"))
	f.Add([]byte("0000"))
	f.Add([]byte("0004"))
	f.Fuzz(func(t *testing.T, in []byte) {
		var out bytes.Buffer
		err := copyRequest(&out, bytes.NewReader(in))
		if !bytes.HasPrefix(in, out.Bytes()) {
			t.Fatalf("copied %q, not a prefix of %q", out.Bytes(), in)
		}
		if err == nil && !bytes.HasSuffix(out.Bytes(), []byte("0000")) {
			t.Fatalf("copied %q without its flush", out.Bytes())
		}
	})
}

func FuzzReadCapabilities(f *testing.F) {
	f.Add([]byte("000eversion 2\n0013ls-refs=unborn\n0000"))
	f.Add([]byte("001e# service=git-upload-pack\n0000000eversion 2\n0000"))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := readCapabilities(bytes.NewReader(in))
		if err != nil {
			return
		}
		if !bytes.HasPrefix(got, []byte("000eversion 2\n")) || !bytes.HasSuffix(got, []byte("0000")) {
			t.Fatalf("readCapabilities(%q) = %q", in, got)
		}
		var out bytes.Buffer
		if err := copyRequest(&out, bytes.NewReader(got)); err != nil || !bytes.Equal(out.Bytes(), got) {
			t.Fatalf("readCapabilities(%q) = %q, which isn't pkt-lines up to a flush", in, got)
		}
	})
}
