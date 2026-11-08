package broker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Listen returns the socket systemd passed in under name, or binds path
// itself. Sockets are world-connectable: the uid check in the broker decides
// who gets an answer, so nobody needs to join a group or log in again.
func Listen(name, path string) (net.Listener, error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) {
		n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
		names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
		for i := range n {
			if i < len(names) && names[i] == name {
				f := os.NewFile(uintptr(3+i), name)
				ln, err := net.FileListener(f)
				f.Close()
				return ln, err
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removing stale socket: %w", err)
	}
	old := syscall.Umask(0o111)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	return ln, err
}
