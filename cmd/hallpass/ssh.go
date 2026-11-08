package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/sshgate"
)

// sshCmd is git's ssh command. For github.com it relays the git command
// through the broker, which holds the key. For any other host it runs the
// real ssh unchanged.
func sshCmd(args []string) error {
	host, command, ok := parseSSH(args)
	if !ok || (host != "github.com" && !strings.HasSuffix(host, "@github.com")) {
		return realSSH(args)
	}
	if user, _, found := strings.Cut(host, "@"); found && user != "git" {
		return fmt.Errorf("GitHub's SSH user is git, not %s", user)
	}
	service, repo, err := sshgate.ParseCommand(command)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", config.Socket("ssh"), 5*time.Second)
	if err != nil {
		return fmt.Errorf("can't reach the hallpass broker: %w", err)
	}
	defer conn.Close()
	hdr, _ := json.Marshal(sshgate.Header{Service: service, Repo: repo.String(), GitProtocol: os.Getenv("GIT_PROTOCOL")})
	if _, err := conn.Write(append(hdr, '\n')); err != nil {
		return err
	}
	go func() {
		io.Copy(conn, os.Stdin)
		if uc, ok := conn.(*net.UnixConn); ok {
			uc.CloseWrite()
		}
	}()
	for {
		kind, data, err := sshgate.ReadFrame(conn)
		if err != nil {
			return errors.New("the broker closed the connection")
		}
		switch kind {
		case sshgate.FrameStdout:
			os.Stdout.Write(data)
		case sshgate.FrameStderr:
			os.Stderr.Write(data)
		case sshgate.FrameExit:
			if len(data) == 1 && data[0] != 0 {
				os.Exit(int(data[0]))
			}
			return nil
		}
	}
}

// parseSSH finds the host and remote command in ssh's arguments, the way git
// passes them: options, then [user@]host, then the command.
func parseSSH(args []string) (host, command string, ok bool) {
	withValue := "BbcDEeFIiJLlmOoPpQRSWw"
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			if i < len(args) {
				return args[i], strings.Join(args[i+1:], " "), true
			}
			return "", "", false
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if len(a) == 2 && strings.ContainsRune(withValue, rune(a[1])) {
				i++
			}
			continue
		}
		return a, strings.Join(args[i+1:], " "), true
	}
	return "", "", false
}

// realSSH runs ssh from PATH, skipping anything that resolves to hallpass.
func realSSH(args []string) error {
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, "ssh")
		if r, err := filepath.EvalSymlinks(p); err != nil || r == self {
			continue
		}
		cmd := exec.Command(p, args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}
	return errors.New("ssh is not on PATH")
}
