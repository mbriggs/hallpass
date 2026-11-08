package client

import (
	"strings"
	"testing"
)

func TestCredentialQuitsForGitHub(t *testing.T) {
	var out, errOut strings.Builder
	Credential("get", strings.NewReader("protocol=https\nhost=github.com\npath=acme/x.git\n"), &out, &errOut)
	if out.String() != "quit=1\n" || !strings.Contains(errOut.String(), "went around") {
		t.Fatalf("out=%q err=%q", out.String(), errOut.String())
	}
	out.Reset()
	Credential("get", strings.NewReader("protocol=https\nhost=gitlab.com\n"), &out, &errOut)
	if out.String() != "" {
		t.Fatalf("answered for another host: %q", out.String())
	}
}
