package sshgate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/policy"
)

// noThin adds the no-thin capability to receive-pack's ref list, so the
// client's pack carries every delta base itself and the broker can read
// every object in it.
func noThin(adv []byte) []byte {
	if len(adv) < 4 {
		return adv
	}
	n, err := strconv.ParseUint(string(adv[:4]), 16, 16)
	if err != nil || n <= 4 || int(n) > len(adv) {
		return adv
	}
	line := adv[4:n]
	nul := bytes.IndexByte(line, 0)
	if nul < 0 || bytes.Contains(line[nul:], []byte(" no-thin")) {
		return adv
	}
	body := bytes.TrimSuffix(line, []byte("\n"))
	body = append(append([]byte{}, body...), []byte(" no-thin\n")...)
	var out bytes.Buffer
	fmt.Fprintf(&out, "%04x", len(body)+4)
	out.Write(body)
	out.Write(adv[n:])
	return out.Bytes()
}

// fetchTrees asks GitHub for commits and their trees, without blobs, with a
// protocol v2 fetch over a new session on client.
func fetchTrees(client *ssh.Client, repo github.Repo, commits []string) (map[string]policy.Object, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	if err := sess.Setenv("GIT_PROTOCOL", "version=2"); err != nil {
		return nil, fmt.Errorf("GitHub didn't accept protocol v2: %w", err)
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.Start(fmt.Sprintf("git-upload-pack '%s/%s.git'", repo.Owner, repo.Name)); err != nil {
		return nil, err
	}
	r := bufio.NewReader(stdout)

	caps := map[string]string{}
	for {
		line, kind, err := pkt(r)
		if err != nil {
			return nil, err
		}
		if kind == flush {
			break
		}
		k, v, _ := strings.Cut(strings.TrimSuffix(string(line), "\n"), "=")
		caps[k] = v
	}
	if !strings.Contains(" "+caps["fetch"]+" ", " filter ") || !strings.Contains(" "+caps["fetch"]+" ", " shallow ") {
		return nil, errors.New("GitHub's fetch doesn't offer filter and shallow")
	}
	var req bytes.Buffer
	put := func(s string) { fmt.Fprintf(&req, "%04x%s", len(s)+4, s) }
	put("command=fetch\n")
	if caps["object-format"] != "" {
		put("object-format=sha1\n")
	}
	req.WriteString("0001")
	put("no-progress\n")
	put("deepen 1\n")
	put("filter blob:none\n")
	for _, c := range commits {
		put("want " + c + "\n")
	}
	put("done\n")
	req.WriteString("0000")
	if _, err := stdin.Write(req.Bytes()); err != nil {
		return nil, err
	}
	stdin.Close()

	// The response is sections: shallow-info, then packfile, whose lines
	// carry the pack on side-band 1. ReadPack reads the pack as it arrives,
	// so only what it keeps stays in memory.
	pr, pw := io.Pipe()
	type result struct {
		p   *policy.Pack
		err error
	}
	done := make(chan result, 1)
	go func() {
		p, err := policy.ReadPack(pr)
		// Take whatever follows, so the loop below never blocks on a
		// reader that has stopped.
		_, _ = io.Copy(io.Discard, pr)
		done <- result{p, err}
	}()
	fail := func(err error) (map[string]policy.Object, error) {
		pw.CloseWithError(err)
		<-done
		return nil, err
	}
	inPack := false
	var n int
	for {
		line, kind, err := pkt(r)
		if err != nil {
			return fail(err)
		}
		switch {
		case kind == flush:
			_ = pw.Close()
			res := <-done
			if res.err != nil {
				return nil, res.err
			}
			return res.p.Objects, nil
		case kind == delim:
		case !inPack && string(line) == "packfile\n":
			inPack = true
		case inPack && len(line) > 0:
			switch line[0] {
			case 1:
				if n += len(line) - 1; n > 1<<30 {
					return fail(errors.New("GitHub's answer is too large"))
				}
				_, _ = pw.Write(line[1:])
			case 3:
				return fail(fmt.Errorf("GitHub: %s", strings.TrimSpace(string(line[1:]))))
			}
		}
	}
}

const (
	data = iota
	flush
	delim
)

// pkt reads one pkt-line, telling flush (0000) and delim (0001) packets
// apart from data.
func pkt(r io.Reader) ([]byte, int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
	if err != nil {
		return nil, 0, errors.New("malformed pkt-line")
	}
	switch {
	case n == 0:
		return nil, flush, nil
	case n == 1:
		return nil, delim, nil
	case n < 4:
		return nil, 0, errors.New("malformed pkt-line")
	}
	buf := make([]byte, n-4)
	_, err = io.ReadFull(r, buf)
	return buf, data, err
}
