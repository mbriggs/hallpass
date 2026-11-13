package sshgate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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
	if login, via, err := s.Check(); err == nil || !strings.Contains(err.Error(), "host key doesn't match") {
		t.Fatalf("Check = %q at %s, %v; want the first address's host key refusal", login, via, err)
	}
}

func TestDialDefaultsToBothGitHubAddresses(t *testing.T) {
	if got := (&Server{}).order(); !slices.Equal(got, []string{"github.com:22", "ssh.github.com:443"}) {
		t.Errorf("default addresses = %v", got)
	}
}

// shorten sets the dial budgets for one test.
func shorten(t *testing.T, quick, full time.Duration) {
	t.Helper()
	q, f := quickDial, fullDial
	quickDial, fullDial = quick, full
	t.Cleanup(func() { quickDial, fullDial = q, f })
}

// listener accepts connections and hands each to serve, closing them all
// when the test ends.
func listener(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go serve(c)
		}
	}()
	return ln.Addr().String()
}

// silent accepts and never speaks, like a tarpit on port 22.
func silent(t *testing.T) string {
	t.Helper()
	return listener(t, func(net.Conn) {})
}

func TestDialFallsBackPastAnAddressThatAcceptsAndGoesSilent(t *testing.T) {
	shorten(t, 200*time.Millisecond, 5*time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	quiet := silent(t)
	addr, hostKey := greeter(t, true, githubGreeting)
	s := &Server{Signer: key, Addrs: []string{quiet, addr}, HostKeys: []string{hostKey}}
	start := time.Now()
	login, via, err := s.Check()
	if err != nil || login != "octocat" || via != addr {
		t.Fatalf("Check = %q, %q, %v; want octocat at %s", login, via, err, addr)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("Check took %v past a silent address with a 200ms budget", took)
	}
	if got := s.order(); !slices.Equal(got, []string{addr, quiet}) {
		t.Errorf("order after falling back = %v", got)
	}
}

func TestDialFallsBackPastAnAddressThatDoesNotSpeakSSH(t *testing.T) {
	for name, serve := range map[string]func(net.Conn){
		"garbage": func(c net.Conn) { c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")); c.Close() },
		"reset": func(c net.Conn) {
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		},
	} {
		t.Run(name, func(t *testing.T) {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			bad := listener(t, serve)
			addr, hostKey := greeter(t, true, githubGreeting)
			s := &Server{Signer: key, Addrs: []string{bad, addr}, HostKeys: []string{hostKey}}
			if login, via, err := s.Check(); err != nil || login != "octocat" || via != addr {
				t.Fatalf("Check = %q, %q, %v; want octocat at %s", login, via, err, addr)
			}
		})
	}
}

func TestDialGivesUpWhenEveryAddressIsSilent(t *testing.T) {
	shorten(t, 200*time.Millisecond, 300*time.Millisecond)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &Server{Signer: key, Addrs: []string{silent(t), silent(t)}, HostKeys: []string{GitHubHostKeys[0]}}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, _, err := s.Check()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Errorf("Check = %v; want a timeout", err)
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("Check took %v with budgets summing to 500ms", took)
		}
		if s.last != "" {
			t.Errorf("remembered %q, which never finished the handshake", s.last)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Check still blocked after 10s on two silent addresses")
	}
}

func TestDialReportsGitHubRefusingTheKey(t *testing.T) {
	hk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hs, _ := ssh.NewSignerFromSigner(hk)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, errors.New("unknown key")
	}}
	cfg.AddHostKey(hs)
	refusing := listener(t, func(c net.Conn) { _, _, _, _ = ssh.NewServerConn(c, cfg) })
	hostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hs.PublicKey())))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &Server{Signer: key, Addrs: []string{refusing, refused(t)}, HostKeys: []string{hostKey}}
	if login, _, err := s.Check(); err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("Check = %q, %v; want the authentication failure", login, err)
	}
}
