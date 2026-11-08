package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mbriggs/hallpass/internal/broker"
	"github.com/mbriggs/hallpass/internal/client"
	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/system"
)

// doctor checks this machine's side: the broker answers, every git reads
// hallpass's config and nothing overrides it, and gh and signing are wired
// up. status --check covers the broker's credentials and GitHub. doctor
// changes nothing.
func doctor(args []string) error {
	d := &checkup{out: os.Stdout}
	d.run()
	if d.failed > 0 {
		return fmt.Errorf("%d checks failed", d.failed)
	}
	return nil
}

type checkup struct {
	out    io.Writer
	failed int
	cfg    *config.Config
	st     *broker.Status
}

func (d *checkup) ok(format string, a ...any) { fmt.Fprintf(d.out, "ok    "+format+"\n", a...) }
func (d *checkup) warn(format string, a ...any) {
	fmt.Fprintf(d.out, "warn  "+format+"\n", a...)
}
func (d *checkup) fail(fix, format string, a ...any) {
	d.failed++
	fmt.Fprintf(d.out, "FAIL  "+format+"\n", a...)
	if fix != "" {
		fmt.Fprintf(d.out, "      fix: %s\n", fix)
	}
}

func (d *checkup) run() {
	if _, err := os.Stat(system.Binary); err != nil {
		d.fail("sudo ./hallpass install", "hallpass isn't installed: %s is missing", system.Binary)
		return
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		d.fail("", "can't read %s: %v", config.Path, err)
		return
	}
	d.cfg = cfg
	if !d.broker() {
		return
	}
	d.gits()
	d.overrides()
	d.gh()
	d.signing()
	d.otherCredentials()
}

func (d *checkup) broker() bool {
	resp, err := client.Ask(config.Socket("hallpass"), broker.Request{Op: "status"})
	if err != nil {
		d.fail("rerun sudo "+system.Binary+" install, then check "+system.LogHint(), "the broker doesn't answer: %v", err)
		return false
	}
	d.st = resp.Status
	d.ok("the broker answers at %s", config.Socket("hallpass"))
	if want := fileHash(system.Binary); d.st.Binary != "" && want != "" && d.st.Binary != want {
		d.fail("sudo "+system.Binary+" install", "the running broker is an older build than %s", system.Binary)
	}
	for _, name := range []string{"git", "gh", "ssh"} {
		c, err := net.DialTimeout("unix", config.Socket(name), 2*time.Second)
		if err != nil {
			d.fail("rerun sudo "+system.Binary+" install", "the %s socket doesn't answer: %v", name, err)
			continue
		}
		c.Close()
	}
	for name, c := range map[string]*broker.CredStatus{"token": d.st.Token, "ssh key": d.st.SSH, "signing key": d.st.Signing} {
		if c != nil && c.Problem != "" {
			d.fail("hallpass status explains; set the credential up again", "the %s didn't load: %s", name, c.Problem)
		}
	}
	if d.st.Token == nil && d.st.SSH == nil && d.st.Signing == nil {
		d.warn("the broker has no credentials yet, so nothing goes through it. See %s help", system.Binary)
	}
	return true
}

// gits checks every git on PATH, and the usual macOS ones, since each may
// read its own system config.
func (d *checkup) gits() {
	if d.cfg.Token == nil && d.cfg.SSH == nil && d.cfg.Signing == nil {
		return
	}
	gits := findGits()
	if len(gits) == 0 {
		d.fail("install git", "there's no git on PATH")
		return
	}
	for _, git := range gits {
		out, _ := exec.Command(git, "config", "--system", "--get-all", "include.path").Output()
		if !strings.Contains("\n"+string(out), "\n"+system.GitConfig+"\n") {
			d.fail("sudo "+git+" config --system --add include.path "+system.GitConfig, "%s doesn't include %s", git, system.GitConfig)
			continue
		}
		if d.cfg.Token != nil && !gitAtLeast(git, 2, 47) {
			d.fail("use git 2.47 or later; on macOS, Homebrew's", "%s is older than 2.47, so its github.com remotes can't reach the broker", git)
			continue
		}
		d.ok("%s reads hallpass's config", git)
	}
}

// overrides checks what the user's git actually resolves, since a global or
// repo setting beats the system config hallpass writes.
func (d *checkup) overrides() {
	git, err := exec.LookPath("git")
	if err != nil {
		return
	}
	get := func(args ...string) (string, string) {
		if args[0] == "--get-urlmatch" {
			// --show-origin doesn't apply to URL matching.
			out, _ := exec.Command(git, append([]string{"config"}, args...)...).Output()
			return strings.TrimSpace(string(out)), "your git config"
		}
		out, _ := exec.Command(git, append([]string{"config", "--show-origin"}, args...)...).Output()
		origin, value, _ := strings.Cut(strings.TrimSpace(string(out)), "\t")
		return value, strings.TrimPrefix(origin, "file:")
	}
	expect := func(what, want, fix string, args ...string) {
		got, from := get(args...)
		if got == want {
			d.ok("%s comes from hallpass", what)
			return
		}
		d.fail(fix, "%s is %q from %s, not hallpass's %q", what, got, orNowhere(from), want)
	}
	if d.cfg.Token != nil {
		// An owner no allowlist entry names, so it takes the HTTPS route.
		const remote, want = "git@github.com:hallpass-doctor/check", "http://github.com/hallpass-doctor/check"
		out, _ := exec.Command(git, "ls-remote", "--get-url", remote).Output()
		if got := strings.TrimSpace(string(out)); got != want {
			d.fail("remove url.*.insteadOf entries for github.com from your own git config", "git rewrites %s to %s, not %s", remote, got, want)
		} else {
			d.ok("git sends github.com remotes to the broker")
		}
		expect("http.proxy for github.com", "socks5h://localhost"+config.RunDir()+"/git.sock",
			"remove http.proxy for github.com from your own git config",
			"--get-urlmatch", "http.proxy", want)
		cmd := exec.Command(git, "credential", "fill")
		cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\npath=x/y\n\n")
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "password=") {
			d.fail("remove credential helpers for github.com from your own git config", "a credential helper other than hallpass's answers for github.com, so git could go around the broker")
		} else {
			d.ok("no other credential helper answers for github.com")
		}
	}
	if d.cfg.SSH != nil {
		expect("core.sshCommand", system.Binary+" ssh", "remove core.sshCommand from your own git config", "--get", "core.sshCommand")
	}
	if d.cfg.Signing != nil {
		fix := "move your own signing settings into a file only git personal loads; the hallpass-setup skill shows how"
		expect("user.signingkey", system.SigningPub, fix, "--get", "user.signingkey")
		expect("gpg.ssh.program", system.SignBinary, fix, "--get", "gpg.ssh.program")
	}
}

func (d *checkup) gh() {
	if d.cfg.Token == nil {
		return
	}
	if _, err := os.Stat(system.GHConfig + "/config.yml"); err != nil {
		d.fail("rerun sudo "+system.Binary+" install", "%s/config.yml is missing", system.GHConfig)
		return
	}
	if _, err := realGH(); err != nil {
		d.warn("gh isn't on PATH, so hallpass gh has nothing to run")
	} else {
		d.ok("hallpass gh can run gh through the broker")
	}
	for _, v := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN"} {
		if os.Getenv(v) != "" {
			d.warn("%s is set. hallpass gh drops it, but plain gh would use it instead of the broker", v)
		}
	}
	if dir := os.Getenv("GH_CONFIG_DIR"); dir != "" && dir != system.GHConfig {
		d.warn("GH_CONFIG_DIR is %s, so plain gh uses that config, not the broker", dir)
	}
}

func (d *checkup) signing() {
	if d.cfg.Signing == nil || d.st.Signing == nil {
		return
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		d.fail("install OpenSSH", "ssh-keygen isn't on PATH; git needs it to verify signatures")
	}
	b, err := os.ReadFile(system.SigningPub)
	if err != nil {
		d.fail("rerun sudo "+system.Binary+" install", "%s is missing", system.SigningPub)
		return
	}
	file, _, _, _, err1 := ssh.ParseAuthorizedKey(b)
	have, _, _, _, err2 := ssh.ParseAuthorizedKey([]byte(d.st.Signing.Public))
	if err1 != nil || err2 != nil || !bytes.Equal(file.Marshal(), have.Marshal()) {
		d.fail("rerun sudo "+system.Binary+" install", "%s isn't the broker's signing key", system.SigningPub)
		return
	}
	d.ok("git signs with the broker's key")
}

// otherCredentials names credentials agents could use to go around the
// broker. Hiding them is a sandbox's job, so these are warnings.
func (d *checkup) otherCredentials() {
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" {
		d.warn("an SSH agent is reachable at %s. Agents can use its keys directly", s)
	}
	home, _ := os.UserHomeDir()
	if b, err := os.ReadFile(filepath.Join(home, ".config", "gh", "hosts.yml")); err == nil && bytes.Contains(b, []byte("oauth_token:")) {
		d.warn("~/.config/gh/hosts.yml holds a gh login. Agents running plain gh use it")
	}
}

func findGits() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		r, err := filepath.EvalSymlinks(p)
		if err != nil || seen[r] {
			return
		}
		if fi, err := os.Stat(r); err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
			return
		}
		seen[r] = true
		out = append(out, p)
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		add(filepath.Join(dir, "git"))
	}
	if runtime.GOOS == "darwin" {
		if exec.Command("xcode-select", "-p").Run() == nil {
			add("/usr/bin/git")
		}
		add("/opt/homebrew/bin/git")
		add("/usr/local/bin/git")
	}
	return out
}

func gitAtLeast(git string, major, minor int) bool {
	out, err := exec.Command(git, "version").Output()
	if err != nil {
		return false
	}
	f := strings.Fields(string(out))
	if len(f) < 3 {
		return false
	}
	var ma, mi int
	fmt.Sscanf(f[2], "%d.%d", &ma, &mi)
	return ma > major || (ma == major && mi >= minor)
}

func orNowhere(s string) string {
	if s == "" {
		return "nowhere"
	}
	return s
}

// fileHash is the SHA-256 of a file, or "" if it can't be read.
func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
