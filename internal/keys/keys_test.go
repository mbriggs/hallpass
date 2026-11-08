package keys

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivateRefusesPlantedFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("keep"), 0o644)
	link := filepath.Join(dir, "key")
	os.Symlink(target, link)
	if err := writePrivate(link, []byte("secret")); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("symlink target changed to %q", b)
	}
	existing := filepath.Join(dir, "existing")
	os.WriteFile(existing, nil, 0o666)
	if err := writePrivate(existing, []byte("secret")); err == nil {
		t.Fatal("reused an existing file")
	}
}

func TestFileBackend(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner("file", filepath.Join(dir, "k"), "")
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadSigner("file", filepath.Join(dir, "k"))
	if err != nil || !again.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(s.Public()) {
		t.Fatalf("reload: %v", err)
	}
	if err := Seal("file", filepath.Join(dir, "t"), []byte("tok")); err != nil {
		t.Fatal(err)
	}
	if b, err := Unseal("file", filepath.Join(dir, "t")); err != nil || string(b) != "tok" {
		t.Fatalf("Unseal = %q, %v", b, err)
	}
	if _, _, err := Split("tpm:relative"); err == nil {
		t.Error("Split accepted a relative path")
	}
}
