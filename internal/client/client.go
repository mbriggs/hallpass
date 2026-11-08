// Package client talks to the broker's control socket and answers git's
// credential helper protocol.
package client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mbriggs/hallpass/internal/broker"
)

// Ask sends one request to the broker and returns its response. A response
// with Error set comes back as an error.
func Ask(socket string, req broker.Request) (broker.Response, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return broker.Response{}, fmt.Errorf("can't reach the hallpass broker at %s: %w", socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return broker.Response{}, err
	}
	var resp broker.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return broker.Response{}, fmt.Errorf("reading broker response: %w", err)
	}
	if resp.Error != "" {
		return resp, fmt.Errorf("%s", resp.Error)
	}
	return resp, nil
}

// Credential answers git's credential helper protocol for github.com. The
// broker never hands out credentials: git reaches github.com through the
// broker, which adds them itself. A request reaching this helper means git
// went around the broker, so the helper tells git to stop instead of letting
// it prompt or fall through to another helper.
func Credential(op string, in io.Reader, out, errOut io.Writer) error {
	if op != "get" {
		return nil // store and erase: nothing to do
	}
	host := ""
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && k == "host" {
			host = v
		}
	}
	if host != "github.com" {
		return nil
	}
	fmt.Fprintln(errOut, "hallpass: git asked for github.com credentials, which means it went around the hallpass broker. Check that git reads /etc/hallpass/gitconfig, or use git personal for your own credentials.")
	fmt.Fprintln(out, "quit=1")
	return nil
}
