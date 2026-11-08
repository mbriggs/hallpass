package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// keepOpen keeps one simulator alive across opens, as a real TPM would be.
type keepOpen struct{ transport.TPMCloser }

func (keepOpen) Close() error { return nil }

func TestTPMSignerAndSeal(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	openTPM = func() (transport.TPMCloser, error) { return keepOpen{sim}, nil }
	sharedTPM = nil
	dir := t.TempDir()

	path := filepath.Join(dir, "ssh.tpm")
	signer, err := NewSigner("tpm", path, "test key")
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := os.ReadFile(path)
	if !strings.Contains(string(blob), "TSS2 PRIVATE KEY") {
		t.Fatalf("stored file isn't a TPM blob:\n%s", blob)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v, want 0600", info.Mode().Perm())
	}
	sum := sha256.Sum256([]byte("payload"))
	sig, err := signer.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pub, sum[:], sig) {
		t.Fatalf("TPM signature doesn't verify (pub %T)", signer.Public())
	}
	again, err := LoadSigner("tpm", path)
	if err != nil || !again.Public().(*ecdsa.PublicKey).Equal(pub) {
		t.Fatalf("reload: %v", err)
	}

	secret := filepath.Join(dir, "token.tpm")
	if err := Seal("tpm", secret, []byte("ghp_example")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(secret); strings.Contains(string(b), "ghp_example") {
		t.Fatal("sealed blob contains the secret")
	}
	got, err := Unseal("tpm", secret)
	if err != nil || string(got) != "ghp_example" {
		t.Fatalf("Unseal = %q, %v", got, err)
	}
	// The broker unseals and then signs for its whole life on one
	// connection, so nothing may stay loaded.
	for i := range 10 {
		if _, err := Unseal("tpm", secret); err != nil {
			t.Fatalf("unseal %d: %v", i, err)
		}
		if _, err := again.Sign(rand.Reader, sum[:], crypto.SHA256); err != nil {
			t.Fatalf("sign %d after unsealing: %v", i, err)
		}
	}
}
