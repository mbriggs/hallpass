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
	"github.com/mbriggs/hallpass/internal/policy"
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

// SpoolDir holds pushed packs while the broker checks them. It's in the
// state dir because the Linux unit lets the broker write only there, and
// its private /tmp may be memory.
func SpoolDir() string { return StateDir() + "/spool" }

// RunDir holds the sockets.
func RunDir() string {
	if runtime.GOOS == "darwin" {
		return "/var/db/hallpass/run"
	}
	return "/run/hallpass"
}

// Socket is where clients find one of the broker's sockets: "hallpass",
// "gh", or "ssh". HALLPASS_RUN_DIR overrides the directory, which only
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
	// Allow and Deny change which operations agents may do, and what they
	// may read, in every repo. A repo entry's own lists override these.
	Allow []Grant `toml:"allow,omitempty"`
	Deny  []Grant `toml:"deny,omitempty"`

	Token   *Token `toml:"token,omitempty"`
	SSH     *Key   `toml:"ssh,omitempty"`
	Signing *Key   `toml:"signing,omitempty"`

	Repos []Repo `toml:"repo"`

	// APIURL, SSHAddr, and SSHHostKeys point the broker at a fake GitHub in
	// tests. SSHHostKeys are authorized_keys lines that replace GitHub's.
	APIURL      string   `toml:"api_url,omitempty"`
	SSHAddr     string   `toml:"ssh_addr,omitempty"`
	SSHHostKeys []string `toml:"ssh_host_keys,omitempty"`
	// SpoolDir is where pushed packs wait while the broker checks them. It
	// defaults to SpoolDir(); a scratch broker that can't write the state
	// dir sets its own.
	SpoolDir string `toml:"spool_dir,omitempty"`
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
	// Allow and Deny override the global lists for the repos this entry
	// covers. An exact entry's lists override an "owner/*" entry's.
	Allow []Grant `toml:"allow,omitempty"`
	Deny  []Grant `toml:"deny,omitempty"`
}

// Grant is one entry of an allow or deny list:
//
//	pr.merge                             an operation
//	field:Repository.hasProjectsEnabled  a field reads may see of a repo or
//	                                     account outside the one named
//	                                     (global lists only)
//	read:deployments/#                   a GET route under /repos/{owner}/{repo}
type Grant string

// Op returns the operation g names, if it names one.
func (g Grant) Op() (op.Op, bool) {
	if strings.Contains(string(g), ":") {
		return "", false
	}
	return op.Op(g), true
}

// Field returns the Type.field g names, if it names one.
func (g Grant) Field() (string, bool) { return strings.CutPrefix(string(g), "field:") }

// Read returns the read pattern g names, if it names one.
func (g Grant) Read() (string, bool) { return strings.CutPrefix(string(g), "read:") }

// Check refuses a grant that names nothing, which would otherwise allow or
// deny nothing, and one no policy may open.
func (g Grant) Check() error {
	if f, ok := g.Field(); ok {
		return policy.CheckField(f)
	}
	if r, ok := g.Read(); ok {
		return policy.CheckRead(r)
	}
	if o, ok := g.Op(); ok {
		if _, known := op.Lookup(string(o)); known {
			return nil
		}
	}
	return fmt.Errorf("no operation is named %q. hallpass policy show lists them; field: and read: name API reads", g)
}

// Rule is what the config says about one repo.
type Rule struct {
	Write bool
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

// Allowed returns the rule for repo. For access, an exact entry wins over
// "owner/*".
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
	return Rule{Write: best.Access != "read", Ops: ops}, true
}

// Anonymous reports whether the broker may send a read it doesn't cover to
// GitHub without the token. repo is the repo the read names, or nil for a
// path outside /repos, which only the global lists decide.
func (c *Config) Anonymous(repo *github.Repo) bool {
	var wild, exact *Repo
	if repo != nil {
		wild, exact = c.entries(*repo)
	}
	for _, d := range c.decide(wild, exact) {
		if d.Op == op.Anonymous {
			return d.On
		}
	}
	return false
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
	apply := func(from string, allow, deny []Grant) {
		for _, g := range allow {
			if o, ok := g.Op(); ok {
				ds[at[o]] = Decision{Op: o, On: true, From: from}
			}
		}
		for _, g := range deny {
			if o, ok := g.Op(); ok {
				ds[at[o]] = Decision{Op: o, On: false, From: from}
			}
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

func (c *Config) API() string {
	if c.APIURL != "" {
		return strings.TrimRight(c.APIURL, "/")
	}
	return "https://api.github.com"
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
	for _, k := range []struct {
		name string
		key  *Key
	}{{"ssh", c.SSH}, {"signing", c.Signing}} {
		if k.key == nil {
			continue
		}
		if _, _, err := keys.Split(k.key.Key); err != nil {
			return fmt.Errorf("%s.key: %w", k.name, err)
		}
	}
	if err := checkGrants("global", c.Allow, c.Deny, true); err != nil {
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
		if err := checkGrants("repo "+r.Match, r.Allow, r.Deny, false); err != nil {
			return err
		}
	}
	return nil
}

// checkGrants refuses a layer's grants that name nothing or that no policy
// may open, a field: grant outside the global lists, and a grant the layer
// both allows and denies.
func checkGrants(layer string, allow, deny []Grant, global bool) error {
	for _, g := range append(slices.Clone(allow), deny...) {
		if err := g.Check(); err != nil {
			return fmt.Errorf("%s: %w", layer, err)
		}
		if _, ok := g.Field(); ok && !global {
			return fmt.Errorf("%s: %s applies to every repo, so it goes in the global lists", layer, g)
		}
	}
	for _, g := range allow {
		if slices.Contains(deny, g) {
			return fmt.Errorf("%s: %s is both allowed and denied", layer, g)
		}
	}
	return nil
}

// Grants is the config's field: and read: grants, for the classifiers.
func (c *Config) Grants() *policy.Grants {
	g := &policy.Grants{Fields: map[string]bool{}}
	for _, x := range c.Allow {
		if f, ok := x.Field(); ok {
			g.Fields[f] = true
		}
	}
	for _, x := range c.Deny {
		if f, ok := x.Field(); ok {
			g.Fields[f] = false
		}
	}
	g.Reads = func(repo github.Repo) []policy.ReadLayer {
		layers := []policy.ReadLayer{readLayer("global", c.Allow, c.Deny)}
		wild, exact := c.entries(repo)
		for _, e := range []*Repo{wild, exact} {
			if e != nil {
				layers = append(layers, readLayer(e.Match, e.Allow, e.Deny))
			}
		}
		return layers
	}
	return g
}

func readLayer(from string, allow, deny []Grant) policy.ReadLayer {
	l := policy.ReadLayer{From: from}
	for _, g := range allow {
		if r, ok := g.Read(); ok {
			l.Allow = append(l.Allow, r)
		}
	}
	for _, g := range deny {
		if r, ok := g.Read(); ok {
			l.Deny = append(l.Deny, r)
		}
	}
	return l
}

// Write saves the config root-owned and world-readable, through a temp file
// so a reader never sees half of it.
func (c *Config) Write(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil { //nolint:gosec // clients read the config as any user; it holds no secrets
		return err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // clients read the config as any user; it holds no secrets
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
