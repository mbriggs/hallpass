package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/mbriggs/hallpass/internal/config"
)

// Files the client config points git at. Tests change them.
var (
	SigningPub     = "/etc/hallpass/signing.pub"
	AllowedSigners = "/etc/hallpass/allowed_signers"
)

// GitConfigText is the git config for the credentials cfg has. Each section
// appears only when its credential exists, so a machine with only a signing
// key leaves git's transport alone.
func GitConfigText(cfg *config.Config) string {
	var b strings.Builder
	b.WriteString("# Written by hallpass from " + config.Path + ". Don't edit; rerun\n")
	b.WriteString("# sudo " + Binary + " install after changing credentials.\n")
	b.WriteString("# Included from git's system config.\n")
	run := config.RunDir()

	forms := func(base string) string {
		return fmt.Sprintf("\tinsteadOf = https://github.com/%s\n\tinsteadOf = git@github.com:%s\n\tinsteadOf = ssh://git@github.com/%s\n", base, base, base)
	}
	if cfg.Token != nil || cfg.SSH != nil {
		b.WriteString(`
# git reaches github.com only through the hallpass broker, which holds the
# credentials and checks every request.
`)
	}
	if cfg.Token != nil {
		b.WriteString(`
# HTTPS: the URL is http:// because the broker, not git, makes the TLS
# connection to GitHub.
[url "http://github.com/"]
` + forms("") + `[http "http://github.com/"]
	proxy = socks5h://localhost` + run + `/git.sock
	followRedirects = false
`)
		for _, owner := range cfg.SSHOwners() {
			b.WriteString("\n# " + owner + " goes over SSH.\n[url \"ssh://git@github.com/" + owner + "/\"]\n" + forms(owner+"/"))
		}
	} else if cfg.SSH != nil {
		b.WriteString("\n[url \"ssh://git@github.com/\"]\n" + forms(""))
	}
	if cfg.SSH != nil {
		b.WriteString(`
# The wrapper sends github.com to the broker and runs ssh for other hosts.
[core]
	sshCommand = ` + Binary + ` ssh
[ssh]
	# Tell git it's OpenSSH-compatible, so it passes -p and GIT_PROTOCOL.
	variant = ssh
`)
	}
	if cfg.Token != nil || cfg.SSH != nil {
		b.WriteString(`
# A request that reaches a credential helper went around the broker. The
# hallpass helper tells git to stop, instead of prompting or falling through
# to a keyring token.
[credential "https://github.com"]
	helper =
	helper = ` + Binary + ` credential
[credential "http://github.com"]
	helper =
	helper = ` + Binary + ` credential
`)
	}
	if cfg.Signing != nil {
		b.WriteString(`
# Commits and tags are signed by the broker's signing key.
[gpg]
	format = ssh
[gpg "ssh"]
	program = ` + SignBinary + `
	allowedSignersFile = ` + AllowedSigners + `
[user]
	signingkey = ` + SigningPub + `
[commit]
	gpgsign = true
[tag]
	gpgsign = true
`)
	}
	b.WriteString(`
[alias]
	# git personal push, git personal fetch, ...: git without this file, so
	# with your own credentials.
	personal = "!GIT_CONFIG_NOSYSTEM=1 git"
`)
	return b.String()
}

// GHConfigText is gh's config.yml for brokered gh. version: "1" stops gh
// from trying to migrate, and failing to write, this read-only file.
func GHConfigText() string {
	return `# Written by hallpass install. gh sends every request to the broker.
version: "1"
git_protocol: https
prompt: disabled
telemetry: disabled
http_unix_socket: ` + config.RunDir() + `/gh.sock
`
}

// GHHostsText makes gh believe it's logged in. The token is a placeholder;
// the broker drops it and adds the real one.
const GHHostsText = `# Written by hallpass install. The token is a placeholder.
github.com:
    users:
        hallpass:
            oauth_token: hallpass-brokered
    git_protocol: https
    oauth_token: hallpass-brokered
    user: hallpass
`

// WriteClientConfig writes the git and gh config for cfg and includes the git
// config from git's system config.
func WriteClientConfig(cfg *config.Config) error {
	if err := os.MkdirAll(filepath.Dir(GitConfig), 0o755); err != nil {
		return err
	}
	if err := writeRoot(GitConfig, GitConfigText(cfg)); err != nil {
		return err
	}
	if cfg.Signing != nil {
		if err := writeRoot(SigningPub, cfg.Signing.Public+"\n"); err != nil {
			return err
		}
		if err := writeRoot(AllowedSigners, `* namespaces="git" `+cfg.Signing.Public+"\n"); err != nil {
			return err
		}
	} else {
		_ = os.Remove(SigningPub)
		_ = os.Remove(AllowedSigners)
	}
	if cfg.Token != nil {
		if err := os.MkdirAll(GHConfig, 0o755); err != nil {
			return err
		}
		if err := writeRoot(GHConfig+"/config.yml", GHConfigText()); err != nil {
			return err
		}
		if err := writeRoot(GHConfig+"/hosts.yml", GHHostsText); err != nil {
			return err
		}
	} else {
		_ = os.RemoveAll(GHConfig)
	}
	gits := gitBinaries()
	if len(gits) == 0 {
		fmt.Fprintf(os.Stderr, "Found no git. Add this to your git's system config:\n  [include]\n  \tpath = %s\n", GitConfig)
		return nil
	}
	for _, git := range gits {
		if err := includeGitConfig(git); err != nil {
			return err
		}
		if cfg.Token != nil && !gitAtLeast(git, 2, 47) {
			fmt.Fprintf(os.Stderr, "%s is older than 2.47, which git over HTTPS through hallpass needs. Its github.com remotes will fail to connect. Use a newer git.\n", git)
		}
	}
	return nil
}

// gitBinaries lists the gits the user might run. Each may read a different
// system config, so each gets the include. Several can share one file, which
// includeGitConfig handles.
func gitBinaries() []string {
	var out []string
	add := func(p string) {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if p, err := exec.LookPath("git"); err == nil {
		add(p)
	}
	if runtime.GOOS == "darwin" {
		// /usr/bin/git is a shim. Without the Command Line Tools it opens
		// their installer instead of running.
		if exec.Command("xcode-select", "-p").Run() == nil {
			add("/usr/bin/git")
		}
		add("/opt/homebrew/bin/git")
		add("/usr/local/bin/git")
	}
	return out
}

func includeGitConfig(git string) error {
	out, _ := exec.Command(git, "config", "--system", "--get-all", "include.path").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == GitConfig {
			return nil
		}
	}
	if err := run(git, "config", "--system", "--add", "include.path", GitConfig); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Included %s from the system config of %s.\n", GitConfig, git)
	return nil
}

// gitAtLeast reports whether git's version is at least major.minor.
func gitAtLeast(git string, major, minor int) bool {
	out, err := exec.Command(git, "version").Output()
	if err != nil {
		return false
	}
	// "git version 2.50.1 (Apple Git-155)"
	f := strings.Fields(string(out))
	if len(f) < 3 {
		return false
	}
	var ma, mi int
	fmt.Sscanf(f[2], "%d.%d", &ma, &mi)
	return ma > major || (ma == major && mi >= minor)
}

// writeRoot replaces path with a root-owned, world-readable file.
func writeRoot(path, content string) error {
	tmp := path + ".new"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
