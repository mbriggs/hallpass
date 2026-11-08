package peer

import (
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

// Peer is who is on the other end of a Unix socket, as the kernel reports it.
type Peer struct {
	Known bool
	UID   uint32
	PID   int32
	// Procs is the client's process chain, nearest first, for the audit log.
	Procs string
}

func Of(conn net.Conn) Peer {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}
	}
	var p Peer
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			return
		}
		p.Known, p.UID = true, cred.Uid
		if pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			p.PID = int32(pid) //nolint:gosec // macOS pids stay below 100000
		}
	}); err != nil {
		return Peer{}
	}
	p.Procs = chain(int(p.PID))
	return p
}

func chain(pid int) string {
	var parts []string
	for i := 0; i < 5 && pid > 1; i++ {
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil {
			break
		}
		name := string(kp.Proc.P_comm[:])
		if j := strings.IndexByte(name, 0); j >= 0 {
			name = name[:j]
		}
		parts = append(parts, name)
		pid = int(kp.Eproc.Ppid)
	}
	return strings.Join(parts, " < ")
}
