package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/mbriggs/hallpass/internal/system"
	"github.com/mbriggs/hallpass/skills"
)

// skillsCmd copies hallpass's agent skills into the skill directories of the
// agents in the user's home.
func skillsCmd(args []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dirs := skills.Dirs(home)
	if len(dirs) == 0 {
		return fmt.Errorf("found neither ~/.claude nor ~/.agents or ~/.codex in %s", home)
	}
	for _, d := range dirs {
		if skills.Current(d) {
			fmt.Fprintf(os.Stderr, "Skills in %s are current.\n", d)
			continue
		}
		if err := skills.Install(d); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Installed the skills in %s.\n", d)
	}
	return nil
}

// offerSkills asks whether to install or update the skills for the user who
// ran sudo, and runs `hallpass skills` as that user. Root never writes into
// the user's home, where an agent could plant a symlink.
func offerSkills(uid uint32) error {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return err
	}
	var stale []string
	verb := "Install"
	for _, d := range skills.Dirs(u.HomeDir) {
		if skills.Current(d) {
			continue
		}
		if _, err := os.Stat(d + "/hallpass-setup"); err == nil {
			verb = "Update"
		}
		stale = append(stale, d)
	}
	if len(stale) == 0 {
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "To install the agent skills, run: %s skills\n", system.Binary)
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s the hallpass agent skills in %s? [Y/n] ", verb, strings.Join(stale, " and "))
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "" && a != "y" && a != "yes" {
		return nil
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return err
	}
	cmd := exec.Command(system.Binary, "skills")
	cmd.Env = []string{"HOME=" + u.HomeDir, "PATH=/usr/bin:/bin"}
	cmd.Dir = u.HomeDir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uint32(gid)}}
	return cmd.Run()
}
