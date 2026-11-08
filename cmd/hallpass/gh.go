package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mbriggs/hallpass/internal/system"
)

// gh runs the real gh with its config pointed at the broker. gh then sends
// every request over the broker's socket, and the broker adds the token. Any
// token in the environment is dropped, so gh can't use one directly.
func gh(args []string) error {
	if _, err := os.Stat(system.GHConfig + "/config.yml"); err != nil {
		return fmt.Errorf("gh through hallpass needs a token, and this machine has none. Get one: sudo %s login", system.Binary)
	}
	real, err := realGH()
	if err != nil {
		return err
	}
	cmd := exec.Command(real, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = ghEnv(os.Environ())
	return cmd.Run()
}

func ghEnv(env []string) []string {
	drop := map[string]bool{
		"GH_TOKEN": true, "GITHUB_TOKEN": true, "GH_ENTERPRISE_TOKEN": true,
		"GITHUB_ENTERPRISE_TOKEN": true, "GH_HOST": true, "GH_CONFIG_DIR": true,
	}
	out := []string{}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	return append(out, "GH_CONFIG_DIR="+system.GHConfig, "GH_NO_UPDATE_NOTIFIER=1", "GH_NO_EXTENSION_UPDATE_NOTIFIER=1")
}

// realGH finds gh on PATH, skipping anything that resolves to hallpass.
func realGH() (string, error) {
	if p := os.Getenv("HALLPASS_GH"); p != "" {
		return p, nil
	}
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, "gh")
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
			continue
		}
		if r, _ := filepath.EvalSymlinks(p); r == self {
			continue
		}
		return p, nil
	}
	return "", errors.New("gh is not on PATH")
}
