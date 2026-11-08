// Package system installs hallpass as a root-owned service.
//
// The service runs the binary in /opt/hallpass/bin. Install copies it there,
// never links it, and refuses to run unless every directory from that one up
// to / is root-owned and not group- or world-writable. Otherwise code running
// as the user could swap the file the broker or a sudo command executes. The
// links in /usr/local/bin are a convenience for the user's shell and are made
// only when that directory passes the same check.
package system

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	Dir    = "/opt/hallpass/bin"
	Binary = Dir + "/hallpass"
	// SignBinary is a link to Binary that git runs as gpg.ssh.program.
	SignBinary = Dir + "/hallpass-sign"
	LinkDir    = "/usr/local/bin"
	GitConfig  = "/etc/hallpass/gitconfig"
	GHConfig   = "/etc/hallpass/gh"
)

//go:embed units
var units embed.FS

// rootPath is the PATH root commands run with. sudo on macOS keeps the
// user's PATH, which would let code running as the user choose what root
// runs by name.
const rootPath = "/usr/sbin:/usr/bin:/sbin:/bin"

// RequireRoot fails unless running as root. Every root command calls it
// first, so it also resets PATH to rootPath.
func RequireRoot(cmd string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s needs root; run it as: sudo %s %s", cmd, Binary, cmd)
	}
	return os.Setenv("PATH", rootPath)
}

// InvokingUID is the uid of the user who ran sudo.
func InvokingUID() (uint32, error) {
	return sudoID("SUDO_UID")
}

func sudoID(name string) (uint32, error) {
	s := os.Getenv(name)
	if s == "" {
		return 0, fmt.Errorf("%s is unset; run with sudo", name)
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

// ServiceIDs looks up the service user's uid and gid.
func ServiceIDs(name string) (uid, gid int, err error) {
	u, err := idOf("-u", name)
	if err != nil {
		return 0, 0, fmt.Errorf("service user %s doesn't exist yet; run install first", name)
	}
	g, err := idOf("-g", name)
	return u, g, err
}

func idOf(flag, name string) (int, error) {
	out, err := exec.Command("id", flag, name).Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// RootControlled checks that dir and each directory above it is a real
// directory owned by root and writable by no one else.
func RootControlled(dir string) error {
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("%s is a symlink", p)
		case !fi.IsDir():
			return fmt.Errorf("%s is not a directory", p)
		case !ok || st.Uid != 0:
			return fmt.Errorf("%s is not owned by root", p)
		case fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0:
			return fmt.Errorf("%s is writable by users other than root", p)
		}
		if p == "/" {
			return nil
		}
	}
}

// installBinary copies the running executable to Binary, then links it into
// LinkDir when that is safe.
func installBinary() error {
	for _, d := range []string{"/opt", "/opt/hallpass", Dir} {
		if err := os.Mkdir(d, 0o755); err != nil && !os.IsExist(err) { //nolint:gosec // every user runs the binaries under these directories
			return err
		}
	}
	for _, d := range []string{"/opt/hallpass", Dir} {
		if err := os.Lchown(d, 0, 0); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // every user runs the binaries under these directories
			return err
		}
	}
	if err := RootControlled(Dir); err != nil {
		return fmt.Errorf("refusing to install: %w", err)
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if self != Binary {
		if err := copyRoot(self, Binary); err != nil {
			return err
		}
	}
	_ = os.Remove(SignBinary)
	if err := os.Symlink("hallpass", SignBinary); err != nil {
		return err
	}

	if err := RootControlled(LinkDir); err != nil {
		fmt.Fprintf(os.Stderr, "Not linking hallpass into %s: %v.\nRun it as %s, or add %s to your PATH.\n", LinkDir, err, Binary, Dir)
		return nil
	}
	link := filepath.Join(LinkDir, "hallpass")
	if fi, err := os.Lstat(link); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s exists and isn't a link; remove it and rerun install", link)
	}
	_ = os.Remove(link)
	return os.Symlink(Binary, link)
}

// copyRoot writes src to dst through a fresh file in dst's directory, which
// is root-controlled, so nothing else can swap the file mid-copy.
func copyRoot(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o755) //nolint:gosec // the installed binary must be executable by every user
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func removeGitConfig() {
	for _, git := range gitBinaries() {
		if cmd, err := gitCommand(git, "config", "--system", "--unset", "--fixed-value", "include.path", GitConfig); err == nil {
			_ = cmd.Run()
		}
	}
	for _, p := range []string{GitConfig, SigningPub, AllowedSigners} {
		_ = os.Remove(p)
	}
	_ = os.RemoveAll(GHConfig)
}

func removeBinary() error {
	link := filepath.Join(LinkDir, "hallpass")
	if t, err := os.Readlink(link); err == nil && t == Binary {
		_ = os.Remove(link)
	}
	if err := os.RemoveAll("/opt/hallpass"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeUnit(name, dst string, mode os.FileMode) error {
	b, err := units.ReadFile("units/" + name)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
