// Package skills holds the agent skills that ship with hallpass and copies
// them into the user's agent skill directories.
package skills

import (
	"bytes"
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed hallpass-*
var files embed.FS

// Dirs returns the skill directories under home for the agents installed
// there: Claude Code reads ~/.claude/skills, Codex reads ~/.agents/skills.
func Dirs(home string) []string {
	var dirs []string
	if exists(filepath.Join(home, ".claude")) {
		dirs = append(dirs, filepath.Join(home, ".claude", "skills"))
	}
	if exists(filepath.Join(home, ".agents")) || exists(filepath.Join(home, ".codex")) {
		dirs = append(dirs, filepath.Join(home, ".agents", "skills"))
	}
	return dirs
}

// Current reports whether every skill in dir matches this binary's copy. A
// skill that is a symlink counts as current: someone links it to a checkout
// on purpose, and Install leaves it alone.
func Current(dir string) bool {
	ok := true
	err := walk(func(name string, data []byte) error {
		if linked(dir, name) {
			return nil
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, data) {
			ok = false
		}
		return nil
	})
	return ok && err == nil
}

// Install replaces each skill in dir with this binary's copy, skipping skills
// that are symlinks.
func Install(dir string) error {
	names, err := fs.Glob(files, "hallpass-*")
	if err != nil {
		return err
	}
	for _, skill := range names {
		dst := filepath.Join(dir, skill)
		if fi, err := os.Lstat(dst); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
	}
	return walk(func(name string, data []byte) error {
		if linked(dir, name) {
			return nil
		}
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // skills are read by agents running as the user who installed them
			return err
		}
		return os.WriteFile(p, data, 0o644) //nolint:gosec // skills are read by agents running as the user who installed them
	})
}

// walk calls fn with each embedded file, and stops at the first error.
func walk(fn func(name string, data []byte) error) error {
	return fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		return fn(filepath.FromSlash(p), data)
	})
}

// linked reports whether the skill holding name is a symlink in dir.
func linked(dir, name string) bool {
	skill := name
	for filepath.Dir(skill) != "." {
		skill = filepath.Dir(skill)
	}
	fi, err := os.Lstat(filepath.Join(dir, skill))
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
