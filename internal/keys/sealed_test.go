package keys

import (
	"bytes"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// useFingerprint makes the sealed backend see fp as this machine's
// fingerprint for the rest of the test.
func useFingerprint(t *testing.T, fp string) {
	t.Helper()
	old := fingerprint
	fingerprint = func() ([]byte, error) { return []byte(fp), nil }
	t.Cleanup(func() { fingerprint = old })
}

func TestSealedRoundTrip(t *testing.T) {
	useFingerprint(t, "mac-a")
	dir := t.TempDir()
	token := []byte("gho_0123456789abcdefghijklmnopqrstuvwxyzAB")
	if err := Seal("sealed", filepath.Join(dir, "t"), token); err != nil {
		t.Fatal(err)
	}
	if got, err := Unseal("sealed", filepath.Join(dir, "t")); err != nil || !bytes.Equal(got, token) {
		t.Fatalf("Unseal = %q, %v", got, err)
	}
	s, err := NewSigner("sealed", filepath.Join(dir, "k"), "")
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadSigner("sealed", filepath.Join(dir, "k"))
	if err != nil || !again.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(s.Public()) {
		t.Fatalf("reload: %v", err)
	}

	// What a secret scanner sweeping the disk would see.
	for _, name := range []string{"t", "k"} {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		if bytes.Contains(b, []byte("gho_")) || bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Errorf("%s holds a recognizable secret: %q", name, b)
		}
	}
	for _, name := range []string{"t", "k", machineSecretName} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, %v", name, fi.Mode(), err)
		}
	}
}

func TestSealedOpensOnlyWithEveryInput(t *testing.T) {
	useFingerprint(t, "mac-a")
	dir := t.TempDir()
	path := filepath.Join(dir, "t")
	if err := Seal("sealed", path, []byte("tok")); err != nil {
		t.Fatal(err)
	}
	secret, _ := os.ReadFile(filepath.Join(dir, machineSecretName))

	t.Run("another machine", func(t *testing.T) {
		useFingerprint(t, "mac-b")
		if _, err := Unseal("sealed", path); !errors.Is(err, errMachineChanged) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the state dir copied without the machine secret", func(t *testing.T) {
		copied := t.TempDir()
		b, _ := os.ReadFile(path)
		os.WriteFile(filepath.Join(copied, "t"), b, 0o600)
		if _, err := Unseal("sealed", filepath.Join(copied, "t")); !errors.Is(err, errMachineChanged) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a different machine secret", func(t *testing.T) {
		other := t.TempDir()
		b, _ := os.ReadFile(path)
		os.WriteFile(filepath.Join(other, "t"), b, 0o600)
		os.WriteFile(filepath.Join(other, machineSecretName), bytes.Repeat([]byte{1}, len(secret)), 0o600)
		if _, err := Unseal("sealed", filepath.Join(other, "t")); !errors.Is(err, errMachineChanged) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a tampered file", func(t *testing.T) {
		b, _ := os.ReadFile(path)
		b[len(b)-1] ^= 1
		bad := filepath.Join(dir, "bad")
		os.WriteFile(bad, b, 0o600)
		if _, err := Unseal("sealed", bad); !errors.Is(err, errMachineChanged) {
			t.Fatalf("err = %v", err)
		}
	})
	if b, err := Unseal("sealed", path); err != nil || string(b) != "tok" {
		t.Fatalf("the original stopped opening: %q, %v", b, err)
	}
}

func TestSealedKeepsOneMachineSecret(t *testing.T) {
	useFingerprint(t, "mac-a")
	dir := t.TempDir()
	Seal("sealed", filepath.Join(dir, "a"), []byte("1"))
	first, _ := os.ReadFile(filepath.Join(dir, machineSecretName))
	Seal("sealed", filepath.Join(dir, "b"), []byte("2"))
	second, _ := os.ReadFile(filepath.Join(dir, machineSecretName))
	if len(first) != 32 || !bytes.Equal(first, second) {
		t.Fatalf("machine secret changed between credentials: %x then %x", first, second)
	}
}

func TestEncodeFingerprintIsUnambiguous(t *testing.T) {
	if bytes.Equal(encodeFingerprint("ab", "c"), encodeFingerprint("a", "bc")) {
		t.Fatal("two different fingerprints encode the same")
	}
}
