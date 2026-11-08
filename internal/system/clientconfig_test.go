package system

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
)

// rewrite asks real git what URL it would use for remote under text.
func rewrite(t *testing.T, text, remote string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "gitconfig")
	os.WriteFile(f, []byte(text), 0o644)
	cmd := exec.Command("git", "ls-remote", "--get-url", remote)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+f)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func TestGitConfigRoutes(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	tok := &config.Token{Secret: "file:/x", Source: "pat"}
	key := &config.Key{Key: "file:/y", Public: "ecdsa-sha2-nistp256 AAAA"}
	both := &config.Config{Token: tok, SSH: key, Repos: []config.Repo{{Match: "acme/*", Via: "ssh"}, {Match: "mbriggs/*"}}}
	cases := []struct {
		cfg          *config.Config
		remote, want string
	}{
		{&config.Config{Token: tok}, "git@github.com:mbriggs/dots.git", "http://github.com/mbriggs/dots.git"},
		{&config.Config{Token: tok}, "https://github.com/mbriggs/dots", "http://github.com/mbriggs/dots"},
		{&config.Config{Token: tok}, "ssh://git@github.com/mbriggs/dots", "http://github.com/mbriggs/dots"},
		{&config.Config{SSH: key}, "https://github.com/mbriggs/dots", "ssh://git@github.com/mbriggs/dots"},
		{both, "https://github.com/acme/widgets", "ssh://git@github.com/acme/widgets"},
		{both, "git@github.com:acme/widgets", "ssh://git@github.com/acme/widgets"},
		{both, "git@github.com:mbriggs/dots", "http://github.com/mbriggs/dots"},
		{&config.Config{Signing: key}, "git@github.com:mbriggs/dots", "git@github.com:mbriggs/dots"},
		{&config.Config{Token: tok}, "https://gitlab.com/x/y", "https://gitlab.com/x/y"},
	}
	for _, c := range cases {
		if got := rewrite(t, GitConfigText(c.cfg), c.remote); got != c.want {
			t.Errorf("%s -> %s, want %s", c.remote, got, c.want)
		}
	}
	signed := GitConfigText(&config.Config{Signing: key})
	if !strings.Contains(signed, "program = "+SignBinary+"\n") || strings.Contains(signed, "sshCommand") {
		t.Errorf("signing-only config:\n%s", signed)
	}
}
