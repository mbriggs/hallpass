// Command scratchcreds makes a scratch broker's credentials with the real
// key backends, so verification exercises the storage the installed broker
// uses: sealed on macOS, file elsewhere.
//
//	scratchcreds [-backend B] DIR TOKEN_FILE
//
// It seals TOKEN_FILE into DIR/token, creates DIR/ssh and DIR/signing as
// P-256 keys, and writes their public keys to DIR/ssh.pub and
// DIR/signing.pub. A credential that already exists is kept. It prints the
// backend, so the caller can write tpm:, sealed:, or file: references.
//
// The default is keys.DefaultBackend(), except that tpm becomes file:
// a scratch broker runs as you, and you may not have access to the TPM.
// Pass -backend tpm to test it anyway.
//
// Build it outside the module's package tree, like fakegithub:
//
//	go build -o "$S/bin/scratchcreds" .claude/skills/verify-hallpass/scripts/scratchcreds/main.go
package main

import (
	"crypto"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mbriggs/hallpass/internal/keys"
)

func main() {
	backend := flag.String("backend", "", "tpm, sealed, or file (default: the platform's, with file for tpm)")
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: scratchcreds [-backend B] DIR TOKEN_FILE")
		os.Exit(2)
	}
	b := *backend
	if b == "" {
		if b = keys.DefaultBackend(); b == "tpm" {
			b = "file"
		}
	}
	if err := run(b, flag.Arg(0), flag.Arg(1)); err != nil {
		fmt.Fprintln(os.Stderr, "scratchcreds:", err)
		os.Exit(1)
	}
	fmt.Println(b)
}

func run(backend, dir, tokenFile string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	token := filepath.Join(dir, "token")
	if _, err := os.Stat(token); errors.Is(err, os.ErrNotExist) {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return err
		}
		if err := keys.Seal(backend, token, b); err != nil {
			return fmt.Errorf("sealing the token: %w", err)
		}
	}
	for _, name := range []string{"ssh", "signing"} {
		path := filepath.Join(dir, name)
		var signer crypto.Signer
		var err error
		if _, statErr := os.Stat(path); statErr == nil {
			signer, err = keys.LoadSigner(backend, path)
		} else {
			signer, err = keys.NewSigner(backend, path, "hallpass verify "+name+" key")
		}
		if err != nil {
			return fmt.Errorf("the %s key: %w", name, err)
		}
		pub, err := ssh.NewPublicKey(signer.Public())
		if err != nil {
			return err
		}
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		if err := os.WriteFile(path+".pub", []byte(line+"\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}
