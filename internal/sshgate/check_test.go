package sshgate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// greeter answers a shell request the way GitHub does: the greeting on
// stderr, exit status 1, and a closed channel. replyFirst says whether it
// answers the shell request before greeting, or closes the channel without
// answering it, which GitHub's timing sometimes amounts to.
func greeter(t *testing.T, replyFirst bool) (addr, hostKey string) {
	t.Helper()
	hk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hs, _ := ssh.NewSignerFromSigner(hk)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(hs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for req := range creqs {
							if req.Type != "shell" {
								req.Reply(false, nil)
								continue
							}
							if replyFirst {
								req.Reply(true, nil)
							}
							ch.Stderr().Write([]byte("Hi octocat! You've successfully authenticated, but GitHub does not provide shell access.\n"))
							var b [4]byte
							binary.BigEndian.PutUint32(b[:], 1)
							ch.SendRequest("exit-status", false, b[:])
							ch.Close()
							return
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hs.PublicKey())))
}

func TestCheckReadsGitHubsGreeting(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, replyFirst := range []bool{true, false} {
		addr, hostKey := greeter(t, replyFirst)
		s := &Server{Signer: key, Addr: addr, HostKeys: []string{hostKey}}
		for i := range 20 {
			login, err := s.Check()
			if err != nil || login != "octocat" {
				t.Fatalf("replyFirst=%v, try %d: Check = %q, %v", replyFirst, i, login, err)
			}
		}
	}
}
