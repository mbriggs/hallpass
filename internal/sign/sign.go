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
	oid   = `[0-9a-f]{40}(?:[0-9a-f]{24})?`
	ident = `[^<>\n]* <[^<>\n]*> [0-9]+ [+-][0-9]{4}`
	// The headers git writes, in the order it writes them. A signature
	// header doesn't match, so an object that's already signed is refused.
	commitHeader = regexp.MustCompile(`^tree ` + oid + `\n(?:parent ` + oid + `\n)*author ` + ident + `\ncommitter ` + ident +
		`\n(?:encoding [^\n]+\n)?(?:mergetag [^\n]*\n(?: [^\n]*\n)*)*$`)
	tagHeader = regexp.MustCompile(`^object ` + oid + `\ntype (?:commit|tree|blob|tag)\ntag [^\n]+\ntagger ` + ident + `\n$`)
)

// Describe checks that data is a git commit or tag object, the only things
// the broker signs, and summarizes it for the audit log.
func Describe(data []byte) (string, error) {
	head, msg, ok := bytes.Cut(data, []byte("\n\n"))
	header := data[:min(len(head)+1, len(data))]
	kind := ""
	switch {
	case !ok || bytes.IndexByte(header, 0) >= 0:
	case commitHeader.Match(header):
		kind = "commit"
	case tagHeader.Match(header):
		kind = "tag"
	}
	if kind == "" {
		return "", errors.New("hallpass only signs unsigned git commits and tags")
	}
	subject, _, _ := bytes.Cut(msg, []byte("\n"))
	if len(subject) > 120 {
		subject = subject[:120]
	}
	return fmt.Sprintf("%s %q", kind, subject), nil
}
