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
	for _, bad := range []string{"hello", "SSHSIG", "tree xyz\n", "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\ngpgsig x\n"} {
		if _, err := Describe([]byte(bad)); err == nil {
			t.Errorf("signed %q", bad)
		}
	}
}
