package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runGHAuth(t *testing.T, stdin string, args ...string) (handled bool, stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	in := strings.NewReader(stdin)
	handled, err = ghAuth(args, in, &out, &errOut)
	if handled && in.Len() != 0 && (args[1] == "git-credential" || strings.Contains(strings.Join(args, " "), "--with-token")) {
		t.Errorf("gh %s left stdin unread", strings.Join(args, " "))
	}
	return handled, out.String(), errOut.String(), err
}

func TestGHAuthReportsLoggedIn(t *testing.T) {
	handled, out, _, err := runGHAuth(t, "", "auth", "status", "--hostname", "github.com")
	if !handled || err != nil || !strings.Contains(out, "✓ Logged in to github.com account hallpass") || strings.Contains(out, ghAuthToken) {
		t.Fatalf("status: handled=%v err=%v out=%q", handled, err, out)
	}
	_, out, _, _ = runGHAuth(t, "", "auth", "status", "-t")
	if !strings.Contains(out, "Token: "+ghAuthToken) {
		t.Fatalf("status -t hides the token: %q", out)
	}

	_, out, _, err = runGHAuth(t, "", "auth", "status", "--json", "hosts")
	var got struct {
		Hosts map[string][]struct{ State, Login string }
	}
	if err != nil || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("status --json: err=%v out=%q", err, out)
	}
	if a := got.Hosts["github.com"]; len(a) != 1 || a[0].State != "success" || a[0].Login != "hallpass" {
		t.Fatalf("status --json: %q", out)
	}

	if _, _, _, err := runGHAuth(t, "", "auth", "status", "--json", "hosts", "--jq", ".hosts"); err == nil {
		t.Fatal("status --jq should say it isn't supported, not print unfiltered JSON")
	}

	_, out, _, _ = runGHAuth(t, "", "auth", "token")
	if out != ghAuthToken+"\n" {
		t.Fatalf("token: %q", out)
	}
}

func TestGHAuthChangesSucceedWithoutDoingAnything(t *testing.T) {
	for _, args := range [][]string{
		{"auth", "login", "--with-token"},
		{"auth", "login", "-h", "github.com", "--web"},
		{"auth", "logout"},
		{"auth", "refresh", "-s", "repo"},
		{"auth", "switch"},
		{"auth", "setup-git"},
		{"auth", "git-credential", "get"},
	} {
		handled, out, _, err := runGHAuth(t, "ghp_secret\n", args...)
		if !handled || err != nil || out != "" {
			t.Errorf("gh %v: handled=%v err=%v stdout=%q", args, handled, err, out)
		}
	}
}

func TestGHAuthLeavesHelpAndOtherCommandsToGH(t *testing.T) {
	for _, args := range [][]string{
		{"auth"},
		{"auth", "status", "--help"},
		{"auth", "something-new"},
		{"pr", "status"},
		{"api", "auth"},
	} {
		if handled, _, _, _ := runGHAuth(t, "", args...); handled {
			t.Errorf("gh %v was handled; it should go to the otherGH gh", args)
		}
	}
}

func TestGHShimWritesRemovesAndProtectsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gh")
	if err := writeShim(path); err != nil {
		t.Fatal(err)
	}
	if !isShim(path) {
		t.Fatal("written shim isn't recognized")
	}
	if err := writeShim(path); err != nil {
		t.Fatalf("rewriting the shim: %v", err)
	}
	if err := removeShim(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("shim still there after remove")
	}

	otherGH := []byte("#!/bin/sh\necho otherGH gh\n")
	os.WriteFile(path, otherGH, 0o755)
	if err := writeShim(path); err == nil {
		t.Fatal("overwrote a gh that isn't a shim")
	}
	if err := removeShim(path); err == nil {
		t.Fatal("removed a gh that isn't a shim")
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, otherGH) {
		t.Fatal("the other gh changed")
	}
}

// The shim runs hallpass gh, which looks up the otherGH gh on PATH. If it found
// the shim, it would run itself forever.
func TestRealGHSkipsShim(t *testing.T) {
	shims, bin := t.TempDir(), t.TempDir()
	if err := writeShim(filepath.Join(shims, "gh")); err != nil {
		t.Fatal(err)
	}
	otherGH := filepath.Join(bin, "gh")
	os.WriteFile(otherGH, []byte("#!/bin/sh\n"), 0o755)
	t.Setenv("HALLPASS_GH", "")
	t.Setenv("PATH", shims+string(os.PathListSeparator)+bin)
	if got, err := realGH(); err != nil || got != otherGH {
		t.Fatalf("realGH = %q, %v; want %q", got, err, otherGH)
	}
	if p, _ := exec.LookPath("gh"); p != filepath.Join(shims, "gh") {
		t.Fatalf("test setup: gh on PATH is %q", p)
	}
}
