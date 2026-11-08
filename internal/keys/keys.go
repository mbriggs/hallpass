// Package keys creates and loads the broker's credentials.
//
// Two kinds live here: ECDSA P-256 signing keys, for SSH authentication and
// for signing commits, and the GitHub token, a secret the broker sends but
// never hands out.
//
// The tpm backend generates signing keys inside this machine's TPM, so the
// private key never exists anywhere else, even for root. It seals the token
// to the TPM, so a copied disk yields nothing. The file backend keeps both in
// files only the service user can read. It is the fallback where there is no
// TPM, and the only choice on macOS.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// NewSigner creates a P-256 key at path, which must not exist yet, and
// returns its signer.
func NewSigner(backend, path, description string) (crypto.Signer, error) {
	switch backend {
	case "file":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := writePrivate(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
			return nil, err
		}
	case "tpm":
		blob, err := createTPM(description)
		if err != nil {
			return nil, err
		}
		if err := writePrivate(path, blob); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown key backend %q", backend)
	}
	return LoadSigner(backend, path)
}

// LoadSigner returns a signer for the key at path.
func LoadSigner(backend, path string) (crypto.Signer, error) {
	switch backend {
	case "file":
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("no PEM block in key file")
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is %T, want ECDSA", k)
		}
		return ek, nil
	case "tpm":
		return loadTPM(path)
	}
	return nil, fmt.Errorf("unknown key backend %q", backend)
}

// Seal stores secret at path, which must not exist yet.
func Seal(backend, path string, secret []byte) error {
	switch backend {
	case "file":
		return writePrivate(path, secret)
	case "tpm":
		blob, err := sealTPM(secret)
		if err != nil {
			return err
		}
		return writePrivate(path, blob)
	}
	return fmt.Errorf("unknown key backend %q", backend)
}

// Unseal reads back a secret Seal stored.
func Unseal(backend, path string) ([]byte, error) {
	switch backend {
	case "file":
		return os.ReadFile(path)
	case "tpm":
		return unsealTPM(path)
	}
	return nil, fmt.Errorf("unknown key backend %q", backend)
}

// HaveTPM reports whether this machine has a TPM resource manager hallpass
// can use.
func HaveTPM() bool { return haveTPM() }

// DefaultBackend is tpm where there is one, and file otherwise.
func DefaultBackend() string {
	if HaveTPM() {
		return "tpm"
	}
	return "file"
}

// Split separates a config reference like "tpm:/var/lib/hallpass/x" into
// its backend and path.
func Split(ref string) (backend, path string, err error) {
	backend, path, ok := strings.Cut(ref, ":")
	if !ok || (backend != "tpm" && backend != "file") || !strings.HasPrefix(path, "/") {
		return "", "", fmt.Errorf("want tpm:/path or file:/path, got %q", ref)
	}
	return backend, path, nil
}

// writePrivate creates path, which must not exist yet. Root writes keys into
// a directory the service user owns, so it never follows a symlink or reuses
// a file someone else could have planted there.
func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
