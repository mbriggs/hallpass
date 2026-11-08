package main

import (
	"path/filepath"
	"testing"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/keys"
)

// Installing the token hallpass already has must not count as replacing it,
// since replacing revokes the old token, which is the same one.
func TestSameToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := keys.Seal("file", path, []byte("ghp_one")); err != nil {
		t.Fatal(err)
	}
	stored := &config.Token{Secret: "file:" + path}
	if !sameToken(stored, "ghp_one") {
		t.Error("the stored token didn't match itself")
	}
	if sameToken(stored, "ghp_two") {
		t.Error("a different token matched")
	}
	if sameToken(&config.Token{Secret: "file:" + path + ".missing"}, "ghp_one") {
		t.Error("a token that won't unseal matched")
	}
}
