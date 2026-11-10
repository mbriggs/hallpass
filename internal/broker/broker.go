// Package broker holds the broker's credentials and answers its control
// socket.
//
// A client sends one JSON request line and reads one JSON response. The kernel
// reports each client's uid, and only uids in the config get an answer. The
// control socket never returns a credential. git and gh reach GitHub through
// the broker's other sockets, which use the credentials themselves.
package broker

import (
	"bufio"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/keys"
	"github.com/mbriggs/hallpass/internal/peer"
	"github.com/mbriggs/hallpass/internal/sign"
)

// Creds are the credentials the broker loaded. Any of them may be missing.
type Creds struct {
	Token   string
	SSH     crypto.Signer
	Signing crypto.Signer
	// Problems explains, per credential, why one the config names didn't
	// load.
	Problems map[string]string
}

// LoadCreds loads whatever credentials cfg names.
func LoadCreds(cfg *config.Config) Creds {
	c := Creds{Problems: map[string]string{}}
	if cfg.Token != nil {
		if b, p, err := keys.Split(cfg.Token.Secret); err != nil {
			c.Problems["token"] = err.Error()
		} else if secret, err := keys.Unseal(b, p); err != nil {
			c.Problems["token"] = "can't unseal the token: " + err.Error()
		} else {
			c.Token = string(secret)
		}
	}
	load := func(name string, k *config.Key) crypto.Signer {
		if k == nil {
			return nil
		}
		b, p, err := keys.Split(k.Key)
		if err != nil {
			c.Problems[name] = err.Error()
			return nil
		}
		s, err := keys.LoadSigner(b, p)
		if err != nil {
			c.Problems[name] = "can't load the key: " + err.Error()
			return nil
		}
		return s
	}
	c.SSH = load("ssh", cfg.SSH)
	c.Signing = load("signing", cfg.Signing)
	return c
}

// Request is what a client sends on the control socket.
type Request struct {
	Op string `json:"op"` // "status" or "sign"
	// Check asks status to confirm the credentials with GitHub.
	Check bool `json:"check,omitempty"`
	// Data is the git object to sign.
	Data []byte `json:"data,omitempty"`
}

// Response is what the broker sends back. Error is set alone on failure.
type Response struct {
	Error     string  `json:"error,omitempty"`
	Status    *Status `json:"status,omitempty"`
	Signature string  `json:"signature,omitempty"`
}

// maxRequest bounds a control request. A commit to sign carries its whole
// message.
const maxRequest = 4 << 20

// Status describes the running broker.
type Status struct {
	Token   *CredStatus `json:"token,omitempty"`
	SSH     *CredStatus `json:"ssh,omitempty"`
	Signing *CredStatus `json:"signing,omitempty"`
	Repos   []string    `json:"repos,omitempty"`
	// Policy lists the global changes to the default operations.
	Policy string `json:"policy,omitempty"`
	// Checked is set when the request asked for a live check against GitHub.
	Checked bool `json:"checked,omitempty"`
	// Version is the running broker's build, and Binary the SHA-256 of
	// its executable, so a client can tell it's running an old install.
	Version string `json:"version,omitempty"`
	Binary  string `json:"binary,omitempty"`
}

// CredStatus describes one credential.
type CredStatus struct {
	Problem    string    `json:"problem,omitempty"`
	Login      string    `json:"login,omitempty"`
	Source     string    `json:"source,omitempty"`
	Created    time.Time `json:"created,omitzero"`
	Expires    time.Time `json:"expires,omitzero"`
	Public     string    `json:"public,omitempty"`
	Addr       string    `json:"addr,omitempty"`
	CheckError string    `json:"check_error,omitempty"`
}

// Server answers the control socket.
type Server struct {
	Config *config.Config
	Creds  Creds
	Log    *slog.Logger
	HTTP   *http.Client
	// SSHCheck confirms GitHub accepts the SSH key, and says which address
	// it reached GitHub at.
	SSHCheck func() (login, addr string, err error)
	Version  string
	Binary   string
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// Permitted reports whether the peer may use the broker at all.
func (s *Server) Permitted(p peer.Peer) bool {
	return p.Known && slices.Contains(s.Config.UIDs, p.UID)
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	p := peer.Of(conn)
	log := s.Log.With("uid", p.UID, "pid", p.PID, "procs", p.Procs)

	resp := s.respond(conn, p, log)
	b, _ := json.Marshal(resp)
	_, _ = conn.Write(append(b, '\n'))
}

func (s *Server) respond(conn net.Conn, p peer.Peer, log *slog.Logger) Response {
	if !s.Permitted(p) {
		log.Warn("refused", "reason", "uid not permitted")
		return Response{Error: fmt.Sprintf("uid %d may not use hallpass", p.UID)}
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64<<10), maxRequest)
	refuse := func(reason string) Response {
		log.Warn("refused", "reason", reason)
		return Response{Error: reason}
	}
	if !sc.Scan() {
		return refuse("empty request")
	}
	var req Request
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
		return refuse("malformed request")
	}
	switch req.Op {
	case "status":
		log.Info("allowed", "op", "status", "check", req.Check)
		return Response{Status: s.status(req.Check)}
	case "sign":
		return s.sign(req.Data, log)
	}
	return refuse(fmt.Sprintf("unknown op %q", req.Op))
}

func (s *Server) sign(data []byte, log *slog.Logger) Response {
	if s.Creds.Signing == nil {
		return Response{Error: "this machine has no signing key. Create one: sudo /opt/hallpass/bin/hallpass signing-key create"}
	}
	what, err := sign.Describe(data)
	if err != nil {
		log.Warn("refused", "op", "sign", "reason", err.Error())
		return Response{Error: err.Error()}
	}
	sig, err := sign.Sign(s.Creds.Signing, data)
	if err != nil {
		log.Error("signing failed", "err", err)
		return Response{Error: "signing failed: " + err.Error()}
	}
	log.Info("signed", "object", what)
	return Response{Signature: string(sig)}
}

func (s *Server) status(check bool) *Status {
	cfg := s.Config
	st := &Status{Checked: check, Version: s.Version, Binary: s.Binary}
	if t := cfg.Token; t != nil {
		st.Token = &CredStatus{Problem: s.Creds.Problems["token"], Login: t.Login, Source: t.Source, Created: t.Created, Expires: t.Expires}
		if check && s.Creds.Token != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			info, err := github.CheckToken(ctx, s.HTTP, cfg.API(), s.Creds.Token)
			switch {
			case err != nil:
				st.Token.CheckError = err.Error()
			case !slices.Equal(info.Scopes, []string{"repo"}):
				st.Token.CheckError = fmt.Sprintf("the token's scopes are %v; hallpass needs exactly [repo]", info.Scopes)
			}
		}
	}
	if k := cfg.SSH; k != nil {
		st.SSH = &CredStatus{Problem: s.Creds.Problems["ssh"], Public: k.Public}
		if check && s.SSHCheck != nil {
			if login, addr, err := s.SSHCheck(); err != nil {
				st.SSH.CheckError = err.Error()
			} else {
				st.SSH.Login, st.SSH.Addr = login, addr
			}
		}
	}
	if k := cfg.Signing; k != nil {
		st.Signing = &CredStatus{Problem: s.Creds.Problems["signing"], Public: k.Public}
	}
	st.Policy = opChanges(cfg.Allow, cfg.Deny)
	for _, r := range cfg.Repos {
		e := r.Match
		if r.Access == "read" {
			e += " (read)"
		}
		if ops := opChanges(r.Allow, r.Deny); ops != "" {
			e += " (" + ops + ")"
		}
		st.Repos = append(st.Repos, e)
	}
	return st
}

// opChanges summarizes a layer's allow and deny lists, like
// "+pr.merge -labels +read:deployments".
func opChanges(allow, deny []config.Grant) string {
	var parts []string
	for _, o := range allow {
		parts = append(parts, "+"+string(o))
	}
	for _, o := range deny {
		parts = append(parts, "-"+string(o))
	}
	return strings.Join(parts, " ")
}
