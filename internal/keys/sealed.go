package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// The sealed backend is for machines without a TPM. It encrypts each
// credential with AES-256-GCM under a key that HKDF derives from two inputs:
//
//   - a random machine secret, created with the first sealed credential in
//     machine.secret beside it, and
//   - this machine's fingerprint, read fresh each time it opens a file.
//
// Neither input is secret from root, so this doesn't stop malware written
// for hallpass. It stops two other things. A sealed file matches no secret
// scanner's pattern, unlike a PEM key or a gho_ token. And a copy of the
// state dir, or a leaked fingerprint, opens nothing by itself: opening a
// file takes the machine secret and every fingerprint input.
//
// A file is sealedMagic, a 32-byte salt, a 12-byte nonce, then the
// ciphertext, with sealedMagic as the additional data.

const (
	sealedMagic = "hallpass-sealed-v1\n"
	// machineSecretName is the machine secret's file name, beside the credentials.
	machineSecretName = "machine.secret"
	saltSize          = 32
)

// fingerprint returns this machine's identifying values, encoded so that no
// two different sets of values encode the same. Tests swap it.
var fingerprint = machineFingerprint

// errMachineChanged means a sealed file didn't open: it was sealed on another
// machine, or this one's fingerprint or machine secret changed since.
var errMachineChanged = errors.New("it doesn't open on this machine. It was sealed on another machine, or this machine's serial number, hardware UUID, data volume, or machine secret changed since. Set the credential up again")

func sealFile(path string, plain []byte) error {
	secret, err := machineSecret(filepath.Dir(path))
	if err != nil {
		return err
	}
	fp, err := fingerprint()
	if err != nil {
		return err
	}
	salt := make([]byte, saltSize)
	rand.Read(salt)
	aead, err := sealedAEAD(secret, fp, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	out := append([]byte(sealedMagic), salt...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plain, []byte(sealedMagic))
	return writePrivate(path, out)
}

func openFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rest, ok := bytes.CutPrefix(b, []byte(sealedMagic))
	if !ok || len(rest) < saltSize+12 {
		return nil, fmt.Errorf("%s isn't a sealed hallpass file", path)
	}
	secret, err := os.ReadFile(filepath.Join(filepath.Dir(path), machineSecretName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errMachineChanged
	} else if err != nil {
		return nil, err
	}
	fp, err := fingerprint()
	if err != nil {
		return nil, err
	}
	salt, rest := rest[:saltSize], rest[saltSize:]
	aead, err := sealedAEAD(secret, fp, salt)
	if err != nil {
		return nil, err
	}
	nonce, ct := rest[:aead.NonceSize()], rest[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, []byte(sealedMagic))
	if err != nil {
		return nil, errMachineChanged
	}
	return plain, nil
}

func sealedAEAD(secret, fp, salt []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, append(append([]byte{}, secret...), fp...), salt, "hallpass sealed v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// machineSecret reads the machine secret in dir, creating it on first use
// with the same owner as dir, which is the service user's state dir.
func machineSecret(dir string) ([]byte, error) {
	path := filepath.Join(dir, machineSecretName)
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	if err := writePrivate(path, secret); err != nil {
		return nil, err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("can't read the owner of %s", dir)
	}
	if err := os.Lchown(path, int(st.Uid), int(st.Gid)); err != nil {
		return nil, err
	}
	return secret, nil
}

// encodeFingerprint length-prefixes each name and value, so the encoding is
// unambiguous whatever the values contain.
func encodeFingerprint(pairs ...string) []byte {
	var b []byte
	for _, s := range pairs {
		b = fmt.Appendf(b, "%d:%s", len(s), s)
	}
	return b
}
