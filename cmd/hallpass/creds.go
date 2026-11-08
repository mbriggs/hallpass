package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/keys"
	"github.com/mbriggs/hallpass/internal/system"
)

const webURL = "https://github.com"

var httpClient = &http.Client{Timeout: 30 * time.Second}

// login runs GitHub's device flow as root, so the token goes from GitHub's
// API into storage without passing through the user's clipboard or any
// process the user owns.
func login(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	newLogin := fs.Bool("new-login", false, "allow a token for a different GitHub account than the current one")
	keepOld := fs.Bool("keep-old", false, "don't revoke the token this replaces")
	fs.Parse(args)
	if err := system.RequireRoot("login"); err != nil {
		return err
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	dc, err := github.StartDeviceLogin(ctx, httpClient, webURL, "repo")
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, `Open %s in any browser, on any machine, and enter:

    %s

GitHub will show this as GitHub CLI asking for the repo scope. Waiting...
`, dc.VerificationURI, dc.UserCode)
	token, err := github.FinishDeviceLogin(ctx, httpClient, webURL, dc)
	if err != nil {
		return err
	}
	return storeToken(cfg, token, "login", *newLogin, *keepOld)
}

// installPAT stores a classic PAT the user created. It reads the token from
// the terminal with echo off, or from stdin, never from argv or the
// environment, where other processes could see it.
func installPAT(args []string) error {
	fs := flag.NewFlagSet("install-pat", flag.ExitOnError)
	newLogin := fs.Bool("new-login", false, "allow a token for a different GitHub account than the current one")
	keepOld := fs.Bool("keep-old", false, "don't revoke the token this replaces")
	fs.Parse(args)
	if err := system.RequireRoot("install-pat"); err != nil {
		return err
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	var token string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, `Create a classic token with only the repo scope, and an expiry of 90 days:
  %s/settings/tokens/new?scopes=repo&description=hallpass-%s
For orgs that use SAML SSO, click Configure SSO next to the token and
authorize each org.

Paste the token (it won't echo): `, webURL, host)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		token = string(b)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("no token on stdin")
		}
		token = line
	}
	return storeToken(cfg, strings.TrimSpace(token), "pat", *newLogin, *keepOld)
}

// storeToken checks token with GitHub, stores it, points the config at it,
// and only then retires the old one, so a bad token leaves the working one in
// place.
func storeToken(cfg *config.Config, token, source string, newLogin, keepOld bool) error {
	switch {
	case source == "pat" && !strings.HasPrefix(token, "ghp_"):
		return errors.New("that isn't a classic PAT (they start with ghp_). Fine-grained tokens need org approval in most orgs, which hallpass is built to avoid")
	case source == "login" && !strings.HasPrefix(token, "gho_"):
		return errors.New("GitHub returned an unexpected kind of token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	info, err := github.CheckToken(ctx, httpClient, cfg.API(), token)
	if err != nil {
		return err
	}
	if !slices.Equal(info.Scopes, []string{"repo"}) {
		return fmt.Errorf("the token's scopes are %v. hallpass needs exactly [repo]: without workflow, GitHub refuses pushes that change .github/workflows, and nothing else is needed", info.Scopes)
	}
	if source == "pat" {
		switch {
		case info.Expires.IsZero():
			return errors.New("the token never expires. Create one with an expiry; 90 days is a good choice")
		case time.Until(info.Expires) > 366*24*time.Hour:
			return errors.New("the token expires more than a year from now. Create one with a shorter expiry")
		case time.Until(info.Expires) > 91*24*time.Hour:
			fmt.Fprintln(os.Stderr, "The token expires in more than 90 days. A shorter expiry limits how long a stolen copy works.")
		}
	}
	if old := cfg.Token; old != nil && !newLogin && !strings.EqualFold(old.Login, info.Login) {
		return fmt.Errorf("the token belongs to %s, but the current one belongs to %s. Pass --new-login to switch accounts", info.Login, old.Login)
	}

	// Replacing a token revokes the old one, which would revoke this one
	// too if it's the same.
	if old := cfg.Token; old != nil && sameToken(old, token) {
		fmt.Fprintf(os.Stderr, "hallpass already has this token for %s. Nothing changed.\n", info.Login)
		return nil
	}

	backend := keys.DefaultBackend()
	path, err := newStatePath("token", backend)
	if err != nil {
		return err
	}
	if err := keys.Seal(backend, path, []byte(token)); err != nil {
		return err
	}
	if err := ownByService(path); err != nil {
		return err
	}
	old := cfg.Token
	cfg.Token = &config.Token{Secret: backend + ":" + path, Source: source, Login: info.Login, Created: time.Now().UTC().Truncate(time.Second), Expires: info.Expires}
	if err := commit(cfg); err != nil {
		removeIfUnused(path, err)
		return err
	}
	if old != nil {
		if !keepOld {
			revokeStored(old)
		}
		removeStored(old.Secret)
	}
	fmt.Fprintf(os.Stderr, "Stored a token for %s, %s.\n", info.Login, storedWhere(backend, path, "sealed to this machine's TPM"))
	if source == "login" {
		fmt.Fprintln(os.Stderr, "Device login tokens don't expire. Run login again every few months; it revokes the old one.")
	}
	if len(cfg.Repos) == 0 {
		fmt.Fprintf(os.Stderr, "Next, let agents use some repos: sudo %s allow OWNER/REPO\n", system.Binary)
	}
	return nil
}

func logout(args []string) error {
	if err := system.RequireRoot("logout"); err != nil {
		return err
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		return err
	}
	if cfg.Token == nil {
		return errors.New("there's no token to remove")
	}
	old := cfg.Token
	cfg.Token = nil
	if err := commit(cfg); err != nil {
		return err
	}
	revokeStored(old)
	removeStored(old.Secret)
	fmt.Fprintln(os.Stderr, "Removed the token. git over HTTPS and gh no longer go through hallpass.")
	return nil
}

// revokeStored asks GitHub to revoke a stored token. Failure is reported, not
// fatal: the token is being retired either way.
// sameToken reports whether t stores token. A token that won't unseal
// counts as different.
func sameToken(t *config.Token, token string) bool {
	b, p, err := keys.Split(t.Secret)
	if err != nil {
		return false
	}
	secret, err := keys.Unseal(b, p)
	return err == nil && subtle.ConstantTimeCompare(secret, []byte(token)) == 1
}

func revokeStored(t *config.Token) {
	b, p, err := keys.Split(t.Secret)
	if err == nil {
		var secret []byte
		if secret, err = keys.Unseal(b, p); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			err = github.Revoke(ctx, httpClient, "https://api.github.com", string(secret))
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't revoke the old token (%v). Revoke it at %s/settings/tokens or %s/settings/applications.\n", err, webURL, webURL)
		return
	}
	fmt.Fprintln(os.Stderr, "Revoked the old token. GitHub emails you about it.")
}

// keyCommand handles ssh-key and signing-key.
func keyCommand(kind string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hallpass %s-key create|remove|show", kind)
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		return err
	}
	slot := &cfg.SSH
	if kind == "signing" {
		slot = &cfg.Signing
	}
	switch args[0] {
	case "show":
		if *slot == nil {
			return fmt.Errorf("there's no %s key. Create one: sudo %s %s-key create", kind, system.Binary, kind)
		}
		fmt.Println((*slot).Public)
		return nil
	case "create":
		if err := system.RequireRoot(kind + "-key create"); err != nil {
			return err
		}
		if *slot != nil {
			return fmt.Errorf("there's already a %s key. Remove it first: sudo %s %s-key remove", kind, system.Binary, kind)
		}
		backend := keys.DefaultBackend()
		path, err := newStatePath(kind, backend)
		if err != nil {
			return err
		}
		host, _ := os.Hostname()
		signer, err := keys.NewSigner(backend, path, "hallpass "+kind+" key on "+host)
		if err != nil {
			return err
		}
		if err := ownByService(path); err != nil {
			return err
		}
		pub, err := ssh.NewPublicKey(signer.Public())
		if err != nil {
			return err
		}
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " hallpass-" + kind + "@" + host
		*slot = &config.Key{Key: backend + ":" + path, Public: line}
		if err := commit(cfg); err != nil {
			removeIfUnused(path, err)
			return err
		}
		where := storedWhere(backend, path, "inside this machine's TPM. It can't leave it")
		use := "an Authentication key"
		if kind == "signing" {
			use = "a Signing key"
		}
		fmt.Fprintf(os.Stderr, "Created the %s key %s.\nAdd it on GitHub as %s, titled hallpass-%s %s:\n  %s/settings/ssh/new\n\n", kind, where, use, kind, host, webURL)
		fmt.Println(line)
		if kind == "ssh" {
			fmt.Fprintln(os.Stderr, "\nFor orgs that use SAML SSO, click Configure SSO next to the key and authorize each org.")
		}
		return nil
	case "remove":
		if err := system.RequireRoot(kind + "-key remove"); err != nil {
			return err
		}
		if *slot == nil {
			return fmt.Errorf("there's no %s key", kind)
		}
		old := *slot
		*slot = nil
		if err := commit(cfg); err != nil {
			return err
		}
		removeStored(old.Key)
		fmt.Fprintf(os.Stderr, "Removed the %s key. Delete it from %s/settings/keys too:\n  %s\n", kind, webURL, old.Public)
		return nil
	}
	return fmt.Errorf("usage: hallpass %s-key create|remove|show", kind)
}

// commit writes the config, regenerates the git and gh config from it, and
// restarts the broker so it loads the change.
func commit(cfg *config.Config) error {
	if err := cfg.Write(config.Path); err != nil {
		return errNotWritten{err}
	}
	if err := system.WriteClientConfig(cfg); err != nil {
		return fmt.Errorf("%w. The config is saved; rerun sudo %s install", err, system.Binary)
	}
	if err := system.Restart(); err != nil {
		return fmt.Errorf("%w. The config is saved; rerun sudo %s install", err, system.Binary)
	}
	return nil
}

// errNotWritten means commit failed before the config changed.
type errNotWritten struct{ error }

func (e errNotWritten) Unwrap() error { return e.error }

// removeIfUnused deletes a new credential file when commit failed before the
// config pointed at it. After that, the config needs the file.
func removeIfUnused(path string, err error) {
	var nw errNotWritten
	if errors.As(err, &nw) {
		os.Remove(path)
	}
}

// newStatePath names a fresh file in the state dir, making the dir if the
// broker hasn't started yet.
func newStatePath(kind, backend string) (string, error) {
	dir := config.StateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := ownByService(dir); err != nil {
		return "", err
	}
	ext, ok := map[string]string{"tpm": "tpm", "sealed": "sealed", "file": "key"}[backend]
	if !ok {
		return "", fmt.Errorf("unknown key backend %q", backend)
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%d.%s", kind, time.Now().UnixNano(), ext)), nil
}

// storedWhere says where a new credential went, for the message after
// creating it. tpm is what to say for the tpm backend.
func storedWhere(backend, path, tpm string) string {
	switch backend {
	case "sealed":
		return "in " + path + ", readable only by " + config.ServiceUser() + " and encrypted under a key tied to this Mac"
	case "file":
		return "in " + path + ", readable only by " + config.ServiceUser()
	}
	return tpm
}

func ownByService(path string) error {
	uid, gid, err := system.ServiceIDs(config.ServiceUser())
	if err != nil {
		return err
	}
	return os.Lchown(path, uid, gid)
}

func removeStored(ref string) {
	if _, p, err := keys.Split(ref); err == nil && strings.HasPrefix(p, config.StateDir()+"/") {
		_ = os.Remove(p)
	}
}
