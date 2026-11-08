package main

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mbriggs/hallpass/internal/broker"
	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/keys"
	"github.com/mbriggs/hallpass/internal/system"
)

func TestMain(m *testing.M) {
	// git runs this test binary as gpg.ssh.program, through a script.
	if os.Getenv("HALLPASS_AS_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	// Under -race, each copy of this binary that git runs would otherwise
	// sleep a second on exit.
	os.Setenv("GORACE", "atexit_sleep_ms=0")
	os.Exit(m.Run())
}

func TestGitSignsThroughBroker(t *testing.T) {
	for _, tool := range []string{"git", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("no " + tool)
		}
	}
	tmp, err := os.MkdirTemp("/tmp", "hpsign")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	signer, err := keys.NewSigner("file", filepath.Join(tmp, "signing.key"), "")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(signer.Public())
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	system.SigningPub = filepath.Join(tmp, "signing.pub")
	system.AllowedSigners = filepath.Join(tmp, "allowed_signers")
	os.WriteFile(system.SigningPub, []byte(line+"\n"), 0o644)
	os.WriteFile(system.AllowedSigners, []byte(`* namespaces="git" `+line+"\n"), 0o644)

	t.Setenv("HALLPASS_RUN_DIR", tmp)
	ln, err := broker.Listen("hallpass", config.Socket("hallpass"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &broker.Server{
		Config: &config.Config{UIDs: []uint32{uint32(os.Getuid())}, Signing: &config.Key{Public: line}},
		Creds:  broker.Creds{Signing: signer},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	go srv.Serve(ln)

	// The same shape as the install: a link named hallpass-sign.
	self, _ := os.Executable()
	script := filepath.Join(tmp, "hallpass-sign")
	if err := os.Symlink(self, script); err != nil {
		t.Fatal(err)
	}
	gc := filepath.Join(tmp, "gitconfig")
	os.WriteFile(gc, []byte(`[gpg]
	format = ssh
[gpg "ssh"]
	program = `+script+`
	allowedSignersFile = `+system.AllowedSigners+`
[user]
	signingkey = `+system.SigningPub+`
	name = a
	email = a@x
[commit]
	gpgsign = true
`), 0o644)
	repo := filepath.Join(tmp, "repo")
	env := append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+gc, "HALLPASS_RUN_DIR="+tmp, "HALLPASS_AS_MAIN=1")
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = repo, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	os.MkdirAll(repo, 0o755)
	run("init", "-q")
	run("commit", "-q", "--allow-empty", "-m", "agent work")
	if out := run("verify-commit", "-v", "HEAD"); !strings.Contains(out, "Good \"git\" signature") {
		t.Errorf("verify-commit:\n%s", out)
	}
}
