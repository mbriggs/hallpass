// Package sshgate is where git over SSH reaches GitHub. git runs
// `hallpass ssh` as its ssh command. For github.com, the wrapper sends the
// remote command to the broker and relays its stdin and stdout. The broker
// opens the SSH connection to GitHub with its own key, runs exactly that
// command, checks pushes, and sends the output back. The wrapper never holds
// a key.
//
// The wrapper sends one JSON header line, then git's stdin, then closes its
// write side. The broker answers with frames: a type byte, a big-endian
// uint32 length, and the data. Type 1 is git's stdout, 2 is stderr, and 3
// carries the exit status in one byte and ends the stream.
package sshgate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"

	"github.com/mbriggs/hallpass/internal/github"
)

// Header is what the wrapper sends first.
type Header struct {
	Service     string `json:"service"` // git-upload-pack or git-receive-pack
	Repo        string `json:"repo"`
	GitProtocol string `json:"git_protocol,omitempty"`
}

const (
	FrameStdout = 1
	FrameStderr = 2
	FrameExit   = 3
)

// WriteFrame writes one frame.
func WriteFrame(w io.Writer, kind byte, data []byte) error {
	if len(data) > math.MaxUint32 {
		return errors.New("frame too large")
	}
	var hdr [5]byte
	hdr[0] = kind
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(data))) //nolint:gosec // the check above keeps len(data) within 32 bits
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > 1<<20 {
		return 0, nil, errors.New("frame too large")
	}
	data := make([]byte, n)
	_, err := io.ReadFull(r, data)
	return hdr[0], data, err
}

var remoteCommand = regexp.MustCompile(`^(git-upload-pack|git-receive-pack) '(/?[A-Za-z0-9._/-]+)'$`)

// ParseCommand reads the command git asks ssh to run, like
// "git-upload-pack 'owner/repo.git'".
func ParseCommand(cmd string) (service string, repo github.Repo, err error) {
	m := remoteCommand.FindStringSubmatch(strings.TrimSpace(cmd))
	if m == nil {
		return "", github.Repo{}, fmt.Errorf("hallpass only runs git fetch and push over SSH, not %q", cmd)
	}
	repo, err = github.ParseRepo(m[2])
	return m[1], repo, err
}
