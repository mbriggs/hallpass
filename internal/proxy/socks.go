package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// socksAccept runs the server side of a SOCKS5 handshake and accepts only
// what git sends for an http:// remote on github.com: no authentication, and
// CONNECT to the domain name github.com on port 80. The broker never dials
// what the client names; it serves the request itself.
func socksAccept(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 5 || hdr[1] == 0 {
		return errors.New("not a SOCKS5 greeting")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		conn.Write([]byte{5, 0xff})
		return errors.New("client offered no usable SOCKS auth method")
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return err
	}

	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return err
	}
	refuse := func(why string) error {
		// Reply 2: connection not allowed by ruleset.
		conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return errors.New(why)
	}
	if req[0] != 5 || req[1] != 1 || req[3] != 3 {
		return refuse("SOCKS request isn't CONNECT to a domain name")
	}
	var n [1]byte
	if _, err := io.ReadFull(conn, n[:]); err != nil {
		return err
	}
	host := make([]byte, int(n[0])+2)
	if _, err := io.ReadFull(conn, host); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(host[len(host)-2:])
	if string(host[:len(host)-2]) != "github.com" || port != 80 {
		return refuse("SOCKS target isn't github.com:80")
	}
	_, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
