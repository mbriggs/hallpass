package peer

import (
	"bytes"
	"fmt"
	"net"
	"os"
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
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return Peer{}
	}
	return Peer{Known: true, UID: cred.Uid, PID: cred.Pid, Procs: chain(int(cred.Pid))}
}

// chain names up to five ancestors of pid, like
// "git-credential-hallpass < git push origin main < claude".
func chain(pid int) string {
	var parts []string
	for i := 0; i < 5 && pid > 1; i++ {
		cmd, ppid, ok := proc(pid)
		if !ok {
			break
		}
		parts = append(parts, cmd)
		pid = ppid
	}
	return strings.Join(parts, " < ")
}

func proc(pid int) (cmd string, ppid int, ok bool) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", 0, false
	}
	// The command name is in parens and may contain spaces; ppid follows
	// the closing paren and the state field.
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return "", 0, false
	}
	fields := strings.Fields(string(stat[i+1:]))
	if len(fields) < 2 {
		return "", 0, false
	}
	fmt.Sscan(fields[1], &ppid)

	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	cmd = strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " "))
	if cmd == "" {
		start := bytes.IndexByte(stat, '(')
		cmd = string(stat[start+1 : i])
	}
	if len(cmd) > 120 {
		cmd = cmd[:120] + "…"
	}
	return cmd, ppid, true
}
