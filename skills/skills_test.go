package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallUpdatesChangedSkills(t *testing.T) {
	dir := t.TempDir()
	if Current(dir) {
		t.Fatal("empty dir reported current")
	}
	if err := Install(dir); err != nil {
		t.Fatal(err)
	}
	if !Current(dir) {
		t.Fatal("not current after Install")
	}
	md := filepath.Join(dir, "hallpass-setup", "SKILL.md")
	if err := os.WriteFile(md, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if Current(dir) {
		t.Fatal("edited skill reported current")
	}
	if err := Install(dir); err != nil {
		t.Fatal(err)
	}
	if !Current(dir) {
		t.Fatal("not current after update")
	}
}

func TestInstallLeavesSymlinkedSkill(t *testing.T) {
	dir, checkout := t.TempDir(), t.TempDir()
	if err := os.Symlink(checkout, filepath.Join(dir, "hallpass-repo")); err != nil {
		t.Fatal(err)
	}
	if err := Install(dir); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "hallpass-repo")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v", err)
	}
	if entries, _ := os.ReadDir(checkout); len(entries) != 0 {
		t.Fatalf("wrote through the symlink: %v", entries)
	}
	if !Current(dir) {
		t.Fatal("not current")
	}
}
