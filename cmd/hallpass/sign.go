package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/mbriggs/hallpass/internal/broker"
	"github.com/mbriggs/hallpass/internal/client"
	"github.com/mbriggs/hallpass/internal/config"
	"golang.org/x/crypto/ssh"
)

// signCmd takes ssh-keygen's arguments, the way git calls gpg.ssh.program.
// It handles "-Y sign -n git -f KEY FILE" by asking the broker when KEY is
// the broker's signing key, and passes everything else, verification and the
// user's own keys, to the real ssh-keygen.
func signCmd(args []string) error {
	op, ns, key, file := parseKeygen(args)
	if op != "sign" || ns != "git" || file == "" || !brokerKey(key) {
		return passKeygen(args)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	resp, err := client.Ask(config.Socket("hallpass"), broker.Request{Op: "sign", Data: data})
	if err != nil {
		return err
	}
	return os.WriteFile(file+".sig", []byte(resp.Signature), 0o644)
}

// parseKeygen reads the parts of an ssh-keygen command line hallpass cares
// about. The last argument that isn't an option's value is the file.
func parseKeygen(args []string) (op, ns, key, file string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch a {
		case "-Y":
			op = next()
		case "-n":
			ns = next()
		case "-f":
			key = next()
		case "-I", "-s", "-O", "-r":
			next()
		case "-U":
		default:
			file = a
		}
	}
	return op, ns, key, file
}

// brokerKey reports whether the public key in path is the broker's signing
// key.
func brokerKey(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	want, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return false
	}
	resp, err := client.Ask(config.Socket("hallpass"), broker.Request{Op: "status"})
	if err != nil || resp.Status.Signing == nil {
		return false
	}
	have, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Status.Signing.Public))
	return err == nil && bytes.Equal(have.Marshal(), want.Marshal())
}

func passKeygen(args []string) error {
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return fmt.Errorf("ssh-keygen isn't on PATH: %w", err)
	}
	cmd := exec.Command(kg, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
