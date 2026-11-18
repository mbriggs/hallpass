package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mbriggs/hallpass/internal/system"
)

// shimMarker is in every shim hallpass writes. realGH skips a gh that has
// it, and gh-shim overwrites or removes only a file that has it.
const shimMarker = "# hallpass gh shim"

// shimText is the gh shim: a script named gh that runs hallpass gh, for
// tools that run gh by name and can't be told to run hallpass gh.
func shimText() string {
	return "#!/bin/sh\n" + shimMarker + ": runs gh through the hallpass broker.\n" +
		"# Written by hallpass gh-shim; remove it with: hallpass gh-shim --remove DIR\n" +
		"exec " + system.Binary + " gh \"$@\"\n"
}

// ghShimCmd writes or removes DIR/gh. DIR defaults to ~/.local/bin.
func ghShimCmd(args []string) error {
	fs := flag.NewFlagSet("gh-shim", flag.ExitOnError)
	remove := fs.Bool("remove", false, "remove the shim instead of writing it")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: hallpass gh-shim [--remove] [DIR]\n\nWrites DIR/gh, a script that runs hallpass gh. DIR defaults to ~/.local/bin.")
	}
	fs.Parse(args)
	if fs.NArg() > 1 {
		fs.Usage()
		os.Exit(2)
	}
	dir := fs.Arg(0)
	if dir == "" {
		if os.Geteuid() == 0 {
			return errors.New("as root, name the directory: hallpass gh-shim DIR")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(home, ".local", "bin")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "gh")
	if *remove {
		return removeShim(path)
	}
	if err := writeShim(path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Wrote %s, which runs %s gh.\n", path, system.Binary)
	warnShadowed(path)
	return nil
}

func writeShim(path string) error {
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() || !isShim(path) {
			return fmt.Errorf("%s exists and isn't a hallpass shim; move it or pick another directory", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // a directory on PATH
		return err
	}
	tmp := path + ".hallpass-tmp"
	if err := os.WriteFile(tmp, []byte(shimText()), 0o755); err != nil { //nolint:gosec // the shim must be executable
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func removeShim(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "%s doesn't exist; nothing to remove.\n", path)
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || !isShim(path) {
		return fmt.Errorf("%s isn't a hallpass shim; leaving it alone", path)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Removed %s.\n", path)
	return nil
}

// isShim reports whether the file at path is a shim hallpass wrote.
func isShim(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	return bytes.Contains(head[:n], []byte(shimMarker))
}

// warnShadowed says so when a gh earlier on PATH would run instead of the
// shim, or when the shim's directory isn't on PATH at all.
func warnShadowed(shim string) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, "gh")
		if p == shim {
			return
		}
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 && !isShim(p) {
			fmt.Fprintf(os.Stderr, "Note: %s comes first on PATH, so gh still runs it. Put %s before %s on PATH.\n", p, filepath.Dir(shim), dir)
			return
		}
	}
	fmt.Fprintf(os.Stderr, "Note: %s isn't on PATH. Add it to the front of PATH for the tools that run gh.\n", filepath.Dir(shim))
}
