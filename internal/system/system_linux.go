package system

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/mbriggs/hallpass/internal/config"
)

// sockets are the broker's socket units, one per protocol.
var sockets = []string{"hallpass.socket", "hallpass-git.socket", "hallpass-gh.socket", "hallpass-ssh.socket"}

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

// LogHint tells the user where the audit log is.
func LogHint() string { return "journalctl -u hallpass" }

// Uninstall stops the broker and removes what Install added. It leaves the
// key and config unless purge is set.
func Uninstall(purge bool) error {
	_ = run("systemctl", append([]string{"disable", "--now", "hallpass.service"}, sockets...)...)
	for _, u := range append([]string{"hallpass.service"}, sockets...) {
		p := "/etc/systemd/system/" + u
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
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
