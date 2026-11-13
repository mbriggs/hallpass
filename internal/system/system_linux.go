package system

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
)

// sockets are the broker's socket units, one per protocol.
var sockets = []string{"hallpass.socket", "hallpass-gh.socket", "hallpass-ssh.socket"}

// retired are units earlier versions installed. Install and Uninstall remove
// them. hallpass-git.socket carried git over HTTPS.
var retired = []string{"hallpass-git.socket"}

// Install creates the service user, copies the binary, writes the git and gh
// config, and starts the sockets. Rerunning it upgrades in place.
func Install(cfg *config.Config) error {
	if err := writeUnit("sysusers.conf", "/etc/sysusers.d/hallpass.conf", 0o644); err != nil {
		return err
	}
	if err := run("systemd-sysusers", "/etc/sysusers.d/hallpass.conf"); err != nil {
		return err
	}
	if err := installBinary(); err != nil {
		return err
	}
	if err := WriteClientConfig(cfg); err != nil {
		return err
	}
	if err := removeUnits(retired); err != nil {
		return err
	}
	for _, u := range append([]string{"hallpass.service"}, sockets...) {
		if err := writeUnit(u, "/etc/systemd/system/"+u, 0o644); err != nil {
			return err
		}
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	// systemd won't start a socket for a service that's already running, so
	// stop the broker first. The sockets start it again on the next
	// connection, with the new binary and config.
	if err := run("systemctl", "stop", "hallpass.service"); err != nil {
		return err
	}
	return run("systemctl", append([]string{"enable", "--now"}, sockets...)...)
}

// Restart makes a running broker pick up a new binary, config, or key. A
// broker that isn't running starts on its next connection.
func Restart() error {
	if exec.Command("systemctl", "is-active", "--quiet", "hallpass.service").Run() == nil {
		return run("systemctl", "restart", "hallpass.service")
	}
	return nil
}

// LogOutput is where the broker writes its log: stderr, which systemd sends
// to the journal.
func LogOutput() io.Writer { return os.Stderr }

// OpenLog reads the broker's log from the journal, oldest first. A nonzero
// since asks the journal for only what came after it.
func OpenLog(since time.Time) (io.ReadCloser, error) {
	args := []string{"--unit=hallpass", "--output=cat", "--no-pager", "--quiet"}
	if !since.IsZero() {
		args = append(args, fmt.Sprintf("--since=@%d", since.Unix()))
	}
	cmd := exec.Command("journalctl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &journal{ReadCloser: out, cmd: cmd, stderr: &stderr}, nil
}

// journal is journalctl's output. Close waits for journalctl and reports
// its failure.
type journal struct {
	io.ReadCloser
	cmd    *exec.Cmd
	stderr *bytes.Buffer
}

func (j *journal) Close() error {
	_, _ = io.Copy(io.Discard, j.ReadCloser)
	if err := j.cmd.Wait(); err != nil {
		return fmt.Errorf("journalctl: %w: %s", err, bytes.TrimSpace(j.stderr.Bytes()))
	}
	return nil
}

// Uninstall stops the broker and removes what Install added. It leaves the
// key and config unless purge is set.
func Uninstall(purge bool) error {
	if err := removeUnits(append(append([]string{"hallpass.service"}, sockets...), retired...)); err != nil {
		return err
	}
	_ = run("systemctl", "daemon-reload")
	removeGitConfig()
	if err := removeBinary(); err != nil {
		return err
	}
	if purge {
		for _, p := range []string{"/var/lib/hallpass", "/etc/hallpass"} {
			if err := os.RemoveAll(p); err != nil {
				return err
			}
		}
		fmt.Fprintln(os.Stderr, "Removed the credentials and config. The hallpass user remains; remove it with userdel hallpass and delete /etc/sysusers.d/hallpass.conf.")
	}
	return nil
}

// removeUnits stops, disables, and deletes units. A unit that was never
// installed is fine.
func removeUnits(units []string) error {
	var present []string
	for _, u := range units {
		if _, err := os.Stat("/etc/systemd/system/" + u); err == nil {
			present = append(present, u)
		}
	}
	if len(present) == 0 {
		return nil
	}
	_ = run("systemctl", append([]string{"disable", "--now"}, present...)...)
	for _, u := range present {
		if err := os.Remove("/etc/systemd/system/" + u); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
