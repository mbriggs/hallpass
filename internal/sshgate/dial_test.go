package sshgate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"slices"
	"strings"
	"testing"
)

// refused returns an address nothing listens on, so connecting fails at once.
func refused(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestDialFallsBackWhenAnAddressRefuses(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	blocked := refused(t)
	addr, hostKey := greeter(t, true, githubGreeting)
	s := &Server{Signer: key, Addrs: []string{blocked, addr}, HostKeys: []string{hostKey}}
	login, via, err := s.Check()
	if err != nil || login != "octocat" || via != addr {
		t.Fatalf("Check = %q, %q, %v; want octocat at %s", login, via, err, addr)
	}
	// The next connection starts with the address that worked.
	if got := s.order(); !slices.Equal(got, []string{addr, blocked}) {
		t.Errorf("order after falling back = %v", got)
	}
}

func TestDialPinsTheFallbacksHostKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	addr, _ := greeter(t, true, githubGreeting)
	_, otherKey := greeter(t, true, githubGreeting)
	s := &Server{Signer: key, Addrs: []string{refused(t), addr}, HostKeys: []string{otherKey}}
	if login, _, err := s.Check(); err == nil || !strings.Contains(err.Error(), "host key doesn't match") {
		t.Fatalf("Check = %q, %v; want a host key refusal", login, err)
	}
}

func TestDialDoesNotFallBackPastAHostKeyMismatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong, _ := greeter(t, true, githubGreeting)
	right, hostKey := greeter(t, true, githubGreeting)
	s := &Server{Signer: key, Addrs: []string{wrong, right}, HostKeys: []string{hostKey}}
	if login, via, err := s.Check(); err == nil {
		t.Fatalf("Check reached %q at %s after the first address presented the wrong host key", login, via)
	}
}

func TestDialDefaultsToBothGitHubAddresses(t *testing.T) {
	if got := (&Server{}).order(); !slices.Equal(got, []string{"github.com:22", "ssh.github.com:443"}) {
		t.Errorf("default addresses = %v", got)
	}
}
