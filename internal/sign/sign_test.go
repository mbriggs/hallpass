package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const commit = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor a <a@x> 1 +0000\ncommitter a <a@x> 1 +0000\n\nagent work\n"

func TestSignVerifiesWithSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, err := Sign(key, []byte(commit))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(&key.PublicKey)
	dir := t.TempDir()
	signers := filepath.Join(dir, "allowed")
	os.WriteFile(signers, []byte(`* namespaces="git" `+string(ssh.MarshalAuthorizedKey(pub))), 0o644)
	sigFile := filepath.Join(dir, "sig")
	os.WriteFile(sigFile, sig, 0o644)
	cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", signers, "-I", "anyone", "-n", "git", "-s", sigFile)
	cmd.Stdin = strings.NewReader(commit)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rejected the signature: %v\n%s", err, out)
	}
	cmd = exec.Command("ssh-keygen", "-Y", "verify", "-f", signers, "-I", "anyone", "-n", "git", "-s", sigFile)
	cmd.Stdin = strings.NewReader(commit + "tampered")
	if err := cmd.Run(); err == nil {
		t.Fatal("ssh-keygen accepted a signature over different data")
	}
}

func TestDescribe(t *testing.T) {
	if d, err := Describe([]byte(commit)); err != nil || d != `commit "agent work"` {
		t.Errorf("commit: %q, %v", d, err)
	}
	tag := "object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\ntype commit\ntag v1\ntagger a <a@x> 1 +0000\n\nrelease\n"
	if _, err := Describe([]byte(tag)); err != nil {
		t.Errorf("tag: %v", err)
	}
	const tree = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"
	const who = "a <a@x> 1 +0000\n"
	for _, good := range []string{
		tree + "parent 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nparent 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor " + who + "committer " + who + "encoding ISO-8859-1\n\nmsg",
		tree + "author " + who + "committer " + who + "mergetag object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n type commit\n tag v1\n\nmerge\n",
		tree + "author " + who + "committer " + who + "\n",
	} {
		if _, err := Describe([]byte(good)); err != nil {
			t.Errorf("refused %q: %v", good, err)
		}
	}
	for _, bad := range []string{
		"hello", "SSHSIG", "tree xyz\n",
		tree + "gpgsig x\n",
		// Only a first line that looks like a commit.
		tree + "THIS IS NOT A GIT COMMIT\x00\xff",
		tree + "author " + who + "committer " + who + "gpgsig x\n\nmsg",
		tree + "author " + who + "committer " + who + "gpgsig-sha256 x\n\nmsg",
		tree + "author " + who + "committer a <a@x>\x00 1 +0000\n\nmsg",
		tree + "author " + who + "committer " + who,
		tree + "committer " + who + "author " + who + "\nmsg",
		tag[:len(tag)-len("\nrelease\n")] + "gpgsig x\n\nrelease\n",
	} {
		if _, err := Describe([]byte(bad)); err == nil {
			t.Errorf("signed %q", bad)
		}
	}
}

// Describe must accept the objects git itself writes.
func TestDescribeAcceptsGitObjects(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	raw := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=A U Thor", "-c", "user.email=a@x", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return string(out)
	}
	git := func(args ...string) string { return strings.TrimSpace(raw(args...)) }
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "first")
	git("commit", "-q", "--allow-empty", "--allow-empty-message", "-m", "")
	git("-c", "i18n.commitEncoding=ISO-8859-1", "commit", "-q", "--allow-empty", "-m", "second\n\nbody")
	git("tag", "-a", "-m", "release", "v1")
	git("checkout", "-q", "-b", "side", "HEAD~1")
	git("commit", "-q", "--allow-empty", "-m", "side")
	git("merge", "-q", "--no-ff", "-m", "merge tag", "v1")
	for _, obj := range []string{"HEAD", "HEAD^2", "HEAD^2^", "HEAD~1", "v1"} {
		kind := git("cat-file", "-t", obj)
		data := raw("cat-file", kind, obj)
		if _, err := Describe([]byte(data)); err != nil {
			t.Errorf("refused git's %s %s: %v\n%s", kind, obj, err, data)
		}
	}
}
