package system

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
)

const (
	plist     = "/Library/LaunchDaemons/com.github.mbriggs.hallpass.plist"
	newsyslog = "/etc/newsyslog.d/hallpass.conf"
	label     = "system/com.github.mbriggs.hallpass"
	user      = "_hallpass"
	// logPath is where launchd sends the broker's output, the audit log.
	logPath = "/var/log/hallpass.log"
)

// Install creates the service user, copies the binary, writes the git and gh
// config, and loads the daemon. Rerunning it upgrades in place.
func Install(cfg *config.Config) error {
	if err := ensureUser(); err != nil {
		return err
	}
	if err := installBinary(); err != nil {
		return err
	}
	if err := WriteClientConfig(cfg); err != nil {
		return err
	}
	uid, gid, err := ServiceIDs(user)
	if err != nil {
		return err
	}
	// Others may traverse the state dir to reach run/, but not list it or
	// read the key beside it.
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{"/var/db/hallpass", 0o711}, {"/var/db/hallpass/run", 0o755}} {
		if err := os.Mkdir(d.path, d.mode); err != nil && !os.IsExist(err) {
			return err
		}
		fi, err := os.Lstat(d.path)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", d.path)
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Lchown(d.path, uid, gid); err != nil {
			return err
		}
	}
	// Keep the credentials out of Time Machine, so no backup holds a copy.
	// The exclusion is an attribute on the directory, so it holds whether or
	// not backups are set up yet.
	if out, err := exec.Command("/usr/bin/tmutil", "addexclusion", "/var/db/hallpass").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't exclude /var/db/hallpass from Time Machine (%v: %s). Run: sudo tmutil addexclusion /var/db/hallpass\n", err, bytes.TrimSpace(out))
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640) //nolint:gosec // the broker's own user and group read the audit log; nobody else can
	if err != nil {
		return err
	}
	logf.Close()
	if err := os.Lchown(logPath, uid, gid); err != nil {
		return err
	}
	// The audit log gets a line per request, so rotate it: 10 MB, five
	// compressed copies.
	if err := os.WriteFile(newsyslog, []byte("# Written by hallpass install.\n"+logPath+"\t"+user+":"+user+"\t640\t5\t10240\t*\tZ\n"), 0o644); err != nil { //nolint:gosec // newsyslog reads its config files as root; 0644 is what macOS ships them with
		return err
	}
	if err := writeUnit("hallpass.plist", plist, 0o644); err != nil {
		return err
	}
	return reload()
}

// reload unloads the daemon if it's loaded, then loads it from the plist.
// bootout can return before launchd has torn the service down, and a
// bootstrap in that window fails with "5: Input/output error", which leaves
// no broker running. So wait for the service to go, and retry the load.
func reload() error {
	_ = exec.Command("launchctl", "bootout", label).Run()
	for i := 0; i < 50 && exec.Command("launchctl", "print", label).Run() == nil; i++ {
		time.Sleep(200 * time.Millisecond)
	}
	var err error
	for range 5 {
		if err = run("launchctl", "bootstrap", "system", plist); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("%w. Load it again with: sudo launchctl bootstrap system %s", err, plist)
}

func Restart() error { return run("launchctl", "kickstart", "-k", label) }

// OpenLog reads the broker's log, with what newsyslog rotated out of it,
// oldest first. The file has no index by time, so since is left to the
// caller's filter.
func OpenLog(time.Time) (io.ReadCloser, error) { return openLogFiles(logPath) }

func Uninstall(purge bool) error {
	_ = exec.Command("launchctl", "bootout", label).Run()
	for _, p := range []string{plist, newsyslog} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	removeGitConfig()
	if err := removeBinary(); err != nil {
		return err
	}
	if purge {
		for _, p := range []string{"/var/db/hallpass", "/etc/hallpass"} {
			if err := os.RemoveAll(p); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stderr, "Removed the credentials and config. Remove the service user with: sudo dscl . -delete /Users/%s && sudo dscl . -delete /Groups/%s\n", user, user)
	}
	return nil
}

// ensureUser creates a hidden system user and group below uid 500.
func ensureUser() error {
	if exec.Command("id", "-u", user).Run() == nil {
		return nil
	}
	id, err := freeID()
	if err != nil {
		return err
	}
	ids := strconv.Itoa(id)
	steps := [][]string{
		{"-create", "/Groups/" + user},
		{"-create", "/Groups/" + user, "PrimaryGroupID", ids},
		{"-create", "/Groups/" + user, "RealName", "hallpass token broker"},
		{"-create", "/Users/" + user},
		{"-create", "/Users/" + user, "UniqueID", ids},
		{"-create", "/Users/" + user, "PrimaryGroupID", ids},
		{"-create", "/Users/" + user, "UserShell", "/usr/bin/false"},
		{"-create", "/Users/" + user, "NFSHomeDirectory", "/var/empty"},
		{"-create", "/Users/" + user, "RealName", "hallpass token broker"},
		{"-create", "/Users/" + user, "IsHidden", "1"},
	}
	for _, s := range steps {
		if err := run("dscl", append([]string{"."}, s...)...); err != nil {
			return err
		}
	}
	return nil
}

// freeID finds an id in 300-499 used by neither a user nor a group.
func freeID() (int, error) {
	used := map[int]bool{}
	for _, q := range [][2]string{{"/Users", "UniqueID"}, {"/Groups", "PrimaryGroupID"}} {
		out, err := exec.Command("dscl", ".", "-list", q[0], q[1]).Output()
		if err != nil {
			return 0, err
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 {
				if n, err := strconv.Atoi(f[1]); err == nil {
					used[n] = true
				}
			}
		}
	}
	for id := 300; id < 500; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, errors.New("no free system uid between 300 and 499")
}
