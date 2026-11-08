// Package sign makes SSH signatures (SSHSIG) for git commits and tags, the
// format `ssh-keygen -Y sign` writes and git and GitHub verify.
package sign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Namespace is the only one the broker signs for. A signature in it can't be
// passed off as an SSH login or a signed file.
const Namespace = "git"

// Sign returns the armored SSHSIG for data.
func Sign(signer crypto.Signer, data []byte) ([]byte, error) {
	s, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, err
	}
	h := sha512.Sum512(data)
	signed := bytes.NewBufferString("SSHSIG")
	signed.Write(ssh.Marshal(struct {
		Namespace, Reserved, Hash, Digest string
	}{Namespace, "", "sha512", string(h[:])}))
	sig, err := s.Sign(rand.Reader, signed.Bytes())
	if err != nil {
		return nil, err
	}
	blob := []byte("SSHSIG")
	blob = append(blob, ssh.Marshal(struct {
		Version   uint32
		PublicKey string
		Namespace string
		Reserved  string
		Hash      string
		Signature string
	}{1, string(s.PublicKey().Marshal()), Namespace, "", "sha512", string(ssh.Marshal(sig))})...)

	enc := base64.StdEncoding.EncodeToString(blob)
	var out strings.Builder
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(enc) > 70 {
		out.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	out.WriteString(enc + "\n-----END SSH SIGNATURE-----\n")
	return []byte(out.String()), nil
}

var (
	commitHead = regexp.MustCompile(`^tree [0-9a-f]{40}(?:[0-9a-f]{24})?\n`)
	tagHead    = regexp.MustCompile(`^object [0-9a-f]{40}(?:[0-9a-f]{24})?\ntype [a-z]+\ntag [^\n]+\n`)
)

// Describe checks that data is a git commit or tag object, the only things
// the broker signs, and summarizes it for the audit log.
func Describe(data []byte) (string, error) {
	kind := ""
	switch {
	case commitHead.Match(data):
		kind = "commit"
	case tagHead.Match(data):
		kind = "tag"
	default:
		return "", errors.New("hallpass only signs git commits and tags")
	}
	if bytes.Contains(data, []byte("\ngpgsig ")) {
		return "", errors.New("the object already carries a signature")
	}
	_, msg, _ := bytes.Cut(data, []byte("\n\n"))
	subject, _, _ := bytes.Cut(msg, []byte("\n"))
	if len(subject) > 120 {
		subject = subject[:120]
	}
	return fmt.Sprintf("%s %q", kind, subject), nil
}
