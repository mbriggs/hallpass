// Package config holds the broker's settings and the platform's fixed paths.
//
// The config file is root-owned and world-readable. It holds no secrets: the
// token and private keys live in files only the broker user can read, and
// the config only names them.
package config

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/keys"
	"github.com/mbriggs/hallpass/internal/op"
)

// Path is where the broker reads its config. Only root writes it.
const Path = "/etc/hallpass/hallpass.toml"

// ServiceUser is the account the broker runs as.
func ServiceUser() string {
	if runtime.GOOS == "darwin" {
		return "_hallpass"
	}
	return "hallpass"
}

// StateDir holds the credentials. Only the service user can enter it.
func StateDir() string {
	if runtime.GOOS == "darwin" {
		return "/var/db/hallpass"
	}
	return "/var/lib/hallpass"
}

// RunDir holds the sockets.
func RunDir() string {
	if runtime.GOOS == "darwin" {
		return "/var/db/hallpass/run"
	}
	return "/run/hallpass"
}

// Socket is where clients find one of the broker's sockets: "hallpass",
// "git", "gh", or "ssh". HALLPASS_RUN_DIR overrides the directory, which only
// changes where that client looks.
func Socket(name string) string {
	dir := RunDir()
	if d := os.Getenv("HALLPASS_RUN_DIR"); d != "" {
		dir = d
	}
	return dir + "/" + name + ".sock"
}

// Config is everything the broker knows. Each credential is optional.
type Config struct {
	// UIDs may use the broker. The kernel reports each client's uid, so this
	// holds regardless of socket permissions.
	UIDs []uint32 `toml:"uids"`
	// ProtectedBranches can't be pushed by agents in any repo, on top of
	// each repo's default branch. A trailing "/*" matches a prefix.
	ProtectedBranches []string `toml:"protected_branches"`
	// Allow and Deny change which operations agents may do in every repo.
	// A repo entry's own lists override these.
	Allow []op.Op `toml:"allow,omitempty"`
	Deny  []op.Op `toml:"deny,omitempty"`

	Token   *Token `toml:"token,omitempty"`
	SSH     *Key   `toml:"ssh,omitempty"`
	Signing *Key   `toml:"signing,omitempty"`

	Repos []Repo `toml:"repo"`

	// APIURL and GitURL point the broker at a fake GitHub in tests.
	APIURL string `toml:"api_url,omitempty"`
	GitURL string `toml:"git_url,omitempty"`
}

// Token is the GitHub token the broker uses for HTTPS git and gh.
type Token struct {
	// Secret names where it's stored: "tpm:/path" or "file:/path".
	Secret string `toml:"secret"`
	// Source is "pat" for a classic PAT the user pasted, or "login" for a
	// device login.
	Source  string    `toml:"source"`
	Login   string    `toml:"login"`
	Created time.Time `toml:"created"`
	// Expires is zero for tokens that don't expire.
	Expires time.Time `toml:"expires,omitzero"`
}

// Key is a P-256 key the broker signs with.
type Key struct {
	Key    string `toml:"key"`
	Public string `toml:"public"` // authorized_keys format
}

// Repo is one allowlist entry.
type Repo struct {
	// Match is "owner/name" or "owner/*".
	Match string `toml:"match"`
	// Access is "write", the default, or "read".
	Access string `toml:"access,omitempty"`
	// Via is "https", the default when there is a token, or "ssh".
	Via string `toml:"via,omitempty"`
	// Allow and Deny override the global lists for the repos this entry
	// covers. An exact entry's lists override an "owner/*" entry's.
	Allow []op.Op `toml:"allow,omitempty"`
	Deny  []op.Op `toml:"deny,omitempty"`
}

// Rule is what the config says about one repo.
type Rule struct {
	Write bool
	Via   string // "https" or "ssh"
	// Ops is what agents may do there, when Write is set.
	Ops op.Set
}

// Decision is whether agents may do one operation in a repo, and which
// layer of the config decided: "default", "global", or an entry's match.
type Decision struct {
	Op   op.Op
	On   bool
	From string
}

// Allowed returns the rule for repo. For access and via, an exact entry
// wins over "owner/*".
func (c *Config) Allowed(repo github.Repo) (Rule, bool) {
	wild, exact := c.entries(repo)
	best := exact
	if best == nil {
		best = wild
	}
	if best == nil {
		return Rule{}, false
	}
	ops := op.Set{}
	for _, d := range c.decide(wild, exact) {
		if d.On {
			ops[d.Op] = true
		}
	}
	return Rule{Write: best.Access != "read", Via: c.via(best), Ops: ops}, true
}

// Decide explains what agents may do in repo, one Decision per operation in
// op.All's order. ok is false when the allowlist doesn't cover repo.
func (c *Config) Decide(repo github.Repo) (ds []Decision, ok bool) {
	wild, exact := c.entries(repo)
	return c.decide(wild, exact), wild != nil || exact != nil
}

// decide applies the layers in order: defaults, global, owner/*, exact.
// The last layer that names an operation decides it.
func (c *Config) decide(wild, exact *Repo) []Decision {
	ds := make([]Decision, len(op.All))
	at := map[op.Op]int{}
	for i, info := range op.All {
		ds[i] = Decision{Op: info.Op, On: info.On, From: "default"}
		at[info.Op] = i
	}
	apply := func(from string, allow, deny []op.Op) {
		for _, o := range allow {
			ds[at[o]] = Decision{Op: o, On: true, From: from}
		}
		for _, o := range deny {
			ds[at[o]] = Decision{Op: o, On: false, From: from}
		}
	}
	apply("global", c.Allow, c.Deny)
	for _, e := range []*Repo{wild, exact} {
		if e != nil {
			apply(e.Match, e.Allow, e.Deny)
		}
	}
	return ds
}

// entries finds the "owner/*" and exact entries covering repo.
func (c *Config) entries(repo github.Repo) (wild, exact *Repo) {
	for i := range c.Repos {
		e := &c.Repos[i]
		owner, name, _ := strings.Cut(e.Match, "/")
		if !strings.EqualFold(owner, repo.Owner) {
			continue
		}
		switch {
		case strings.EqualFold(name, repo.Name):
			exact = e
		case name == "*":
			wild = e
		}
	}
	return wild, exact
}

func (c *Config) via(e *Repo) string {
	switch {
	case e.Via != "":
		return e.Via
	case c.Token == nil && c.SSH != nil:
		return "ssh"
	default:
		return "https"
	}
}

// SSHOwners lists owners whose entries route over SSH while a token exists.
// The generated git config sends them to SSH instead of HTTPS.
func (c *Config) SSHOwners() []string {
	var out []string
	seen := map[string]bool{}
	for i := range c.Repos {
		owner, _, _ := strings.Cut(c.Repos[i].Match, "/")
		if c.via(&c.Repos[i]) == "ssh" && !seen[strings.ToLower(owner)] {
			seen[strings.ToLower(owner)] = true
			out = append(out, owner)
		}
	}
	return out
}

func (c *Config) API() string {
	if c.APIURL != "" {
		return strings.TrimRight(c.APIURL, "/")
	}
	return "https://api.github.com"
}

func (c *Config) Git() string {
	if c.GitURL != "" {
		return strings.TrimRight(c.GitURL, "/")
	}
	return "https://github.com"
}

// Load reads the config. A missing file is an empty config: the broker runs
// and refuses everything until root adds credentials.
func Load(path string) (*Config, error) {
	var c Config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		if os.IsNotExist(err) {
			return &c, nil
		}
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if c.Token != nil {
		if _, _, err := keys.Split(c.Token.Secret); err != nil {
			return fmt.Errorf("token.secret: %w", err)
		}
		if c.Token.Source != "pat" && c.Token.Source != "login" {
			return fmt.Errorf("token.source must be pat or login, got %q", c.Token.Source)
		}
	}
	for name, k := range map[string]*Key{"ssh": c.SSH, "signing": c.Signing} {
		if k == nil {
			continue
		}
		if _, _, err := keys.Split(k.Key); err != nil {
			return fmt.Errorf("%s.key: %w", name, err)
		}
	}
	if err := checkOps("global", c.Allow, c.Deny); err != nil {
		return err
	}
	for _, r := range c.Repos {
		owner, name, ok := strings.Cut(r.Match, "/")
		if !ok {
			return fmt.Errorf("repo match %q: want owner/name or owner/*", r.Match)
		}
		if name == "*" {
			name = "x"
		}
		if _, err := github.ParseRepo(owner + "/" + name); err != nil {
			return fmt.Errorf("repo match %q: %w", r.Match, err)
		}
		if r.Access != "" && r.Access != "read" && r.Access != "write" {
			return fmt.Errorf("repo %s: access must be read or write", r.Match)
		}
		if err := checkOps("repo "+r.Match, r.Allow, r.Deny); err != nil {
			return err
		}
		if r.Via != "" && r.Via != "https" && r.Via != "ssh" {
			return fmt.Errorf("repo %s: via must be https or ssh", r.Match)
		}
	}
	return nil
}

// checkOps refuses unknown names, which would otherwise deny nothing, and
// an operation one layer both allows and denies.
func checkOps(layer string, allow, deny []op.Op) error {
	for _, o := range append(slices.Clone(allow), deny...) {
		if _, ok := op.Lookup(string(o)); !ok {
			return fmt.Errorf("%s: no operation is named %q. hallpass policy show lists them", layer, o)
		}
	}
	for _, o := range allow {
		if slices.Contains(deny, o) {
			return fmt.Errorf("%s: %s is both allowed and denied", layer, o)
		}
	}
	return nil
}

// Write saves the config root-owned and world-readable, through a temp file
// so a reader never sees half of it.
func (c *Config) Write(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	fmt.Fprintln(f, "# Written by hallpass. Holds no secrets. Edit it with hallpass allow,")
	fmt.Fprintln(f, "# disallow, policy, login, install-pat, ssh-key, and signing-key, as root.")
	if err := toml.NewEncoder(f).Encode(c); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func dirOf(path string) string {
	i := strings.LastIndexByte(path, '/')
	if i <= 0 {
		return "/"
	}
	return path[:i]
}
