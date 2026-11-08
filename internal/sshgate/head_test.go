package sshgate

import (
	"fmt"
	"strings"
	"testing"
)

func adv(lines ...string) []byte {
	var b strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&b, "%04x%s\n", len(l)+5, l)
	}
	b.WriteString("0000")
	return []byte(b.String())
}

// The default branch is "" only for a repo with no refs at all, so an
// advertisement that loses HEAD can't pass as an empty repo.
func TestHeadBranch(t *testing.T) {
	id := strings.Repeat("a", 40)
	zero := strings.Repeat("0", 40)
	cases := []struct {
		name    string
		adv     []byte
		want    string
		wantErr bool
	}{
		{"normal", adv(id+" HEAD\x00multi_ack symref=HEAD:refs/heads/main agent=git/2", id+" refs/heads/main"), "main", false},
		{"empty repo", adv(zero + " capabilities^{}\x00multi_ack agent=git/2"), "", false},
		{"branches, no HEAD", adv(id+" refs/heads/main\x00multi_ack agent=git/2", id+" refs/heads/colleague"), "", true},
		{"empty HEAD target", adv(id + " HEAD\x00symref=HEAD:refs/heads/ agent=git/2"), "", true},
	}
	for _, c := range cases {
		got, err := headBranch(c.adv)
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("%s: headBranch = %q, %v", c.name, got, err)
		}
	}
}
