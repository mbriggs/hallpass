// Command hallpass lets coding agents use git and gh on GitHub without ever
// holding a credential. A broker running as its own user holds a GitHub
// token, an SSH key, and a signing key, each optional, and uses them itself
// for requests its policy allows.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mbriggs/hallpass/internal/broker"
	"github.com/mbriggs/hallpass/internal/client"
	"github.com/mbriggs/hallpass/internal/config"
	"github.com/mbriggs/hallpass/internal/proxy"
	"github.com/mbriggs/hallpass/internal/sshgate"
	"github.com/mbriggs/hallpass/internal/system"
)

var version = "dev"

const usage = `hallpass: brokered GitHub credentials for coding agents

Setup, as root through /opt/hallpass/bin/hallpass. Each credential is
optional; set up the ones you want:
  sudo ./hallpass install              install into /opt/hallpass, start the broker
  sudo hallpass login                  get a GitHub token by device login, for HTTPS git and gh
  sudo hallpass install-pat            or paste a classic PAT with only the repo scope
  sudo hallpass ssh-key create         make a TPM SSH key, for git over SSH
  sudo hallpass signing-key create     make a TPM signing key, for signed commits
  sudo hallpass allow OWNER/REPO       let agents use a repo; OWNER/* for all of an owner's
  hallpass status --check              confirm the broker's credentials with GitHub
  hallpass doctor                      check this machine's git, gh, and signing setup
  hallpass skills                      install or update the agent skills; install offers this

Daily use. git calls these for you:
  hallpass gh ARGS...                  run gh through the broker
  git personal ARGS...                 run git with your own credentials instead

Maintenance, as root:
  allow OWNER/REPO [--read] [--via ssh]
  disallow OWNER/REPO
  policy allow|deny|reset OP... [--repo OWNER/REPO]
                                       change what agents may do, everywhere or in one repo
  policy show [OWNER/REPO]             list the operations and what's in effect
  ledger add OWNER/REPO BRANCH         let agents update a branch they didn't create
  ledger list OWNER/REPO               list the branches agents may update
  ssh-key remove | signing-key remove | logout
  uninstall [--purge]
  serve                                the broker itself; systemd or launchd runs it
`

func main() {
	// git runs gpg.ssh.program without arguments of its own, so signing has
	// its own name: a link to this binary.
	if filepath.Base(os.Args[0]) == "hallpass-sign" {
		if err := signCmd(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "hallpass:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "install":
		err = install(args)
	case "uninstall":
		err = uninstall(args)
	case "login":
		err = login(args)
	case "install-pat":
		err = installPAT(args)
	case "logout":
		err = logout(args)
	case "ssh-key":
		err = keyCommand("ssh", args)
	case "signing-key":
		err = keyCommand("signing", args)
	case "allow":
		err = allow(args)
	case "disallow":
		err = disallow(args)
	case "policy":
		err = policyCmd(args)
	case "status":
		err = status(args)
	case "doctor":
		err = doctor(args)
	case "ledger":
		err = ledger(args)
	case "skills":
		err = skillsCmd(args)
	case "gh":
		err = gh(args)
	case "sign":
		err = signCmd(args)
	case "ssh":
		err = sshCmd(args)
	case "credential":
		op := ""
		if len(args) > 0 {
			op = args[0]
		}
		err = client.Credential(op, os.Stdin, os.Stdout, os.Stderr)
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "hallpass: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "hallpass:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", config.Path, "config file")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	creds := broker.LoadCreds(cfg)
	for name, p := range creds.Problems {
		log.Error("credential didn't load", "credential", name, "problem", p)
	}
	self, _ := os.Executable()
	ctl := &broker.Server{Config: cfg, Creds: creds, Log: log, Version: version, Binary: fileHash(self)}

	px := &proxy.Server{
		Config:    cfg,
		Token:     creds.Token,
		Ledger:    proxy.OpenLedger(config.StateDir() + "/branches.jsonl"),
		Log:       log,
		Permitted: ctl.Permitted,
	}

	var listeners []net.Listener
	listen := func(name string) (net.Listener, error) {
		ln, err := broker.Listen(name, config.Socket(name))
		if err == nil {
			listeners = append(listeners, ln)
		}
		return ln, err
	}
	ctlLn, err := listen("hallpass")
	if err != nil {
		return err
	}
	gitLn, err := listen("git")
	if err != nil {
		return err
	}
	ghLn, err := listen("gh")
	if err != nil {
		return err
	}
	sshLn, err := listen("ssh")
	if err != nil {
		return err
	}
	gate := &sshgate.Server{Config: cfg, Signer: creds.SSH, Ledger: px.Ledger, Log: log, Permitted: ctl.Permitted}
	if creds.SSH != nil {
		ctl.SSHCheck = gate.Check
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		for _, l := range listeners {
			l.Close()
		}
	}()
	errs := make(chan error, 4)
	go func() { errs <- gate.Serve(sshLn) }()
	go func() { errs <- px.ServeGit(gitLn) }()
	go func() { errs <- px.ServeGH(ghLn) }()
	go func() { errs <- ctl.Serve(ctlLn) }()
	log.Info("serving", "token", creds.Token != "", "ssh", creds.SSH != nil, "signing", creds.Signing != nil, "repos", len(cfg.Repos))
	return <-errs
}

func install(args []string) error {
	if err := system.RequireRoot("install"); err != nil {
		return err
	}
	cfg, err := config.Load(config.Path)
	if err != nil {
		return err
	}
	if len(cfg.UIDs) == 0 {
		uid, err := system.InvokingUID()
		if err != nil {
			return err
		}
		cfg.UIDs = []uint32{uid}
		cfg.ProtectedBranches = []string{"main", "master", "release/*", "production"}
		if err := cfg.Write(config.Path); err != nil {
			return err
		}
	}
	if err := system.Install(cfg); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Installed %s and started the broker.\n", system.Binary)
	if uid, err := system.InvokingUID(); err == nil {
		if err := offerSkills(uid); err != nil {
			fmt.Fprintln(os.Stderr, "hallpass: skills:", err)
		}
	}
	if cfg.Token == nil && cfg.SSH == nil && cfg.Signing == nil {
		fmt.Fprintf(os.Stderr, "Next, set up the credentials you want. See: %s help\n", system.Binary)
	}
	return nil
}

func uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also revoke the token and delete the credentials and config")
	fs.Parse(args)
	if err := system.RequireRoot("uninstall"); err != nil {
		return err
	}
	cfg, _ := config.Load(config.Path)
	if *purge && cfg != nil && cfg.Token != nil {
		revokeStored(cfg.Token)
	}
	if err := system.Uninstall(*purge); err != nil {
		return err
	}
	if *purge && cfg != nil && (cfg.SSH != nil || cfg.Signing != nil) {
		fmt.Fprintln(os.Stderr, "Delete hallpass's keys from https://github.com/settings/keys too.")
	}
	return nil
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	check := fs.Bool("check", false, "also confirm the credentials with GitHub")
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Parse(args)

	socket := config.Socket("hallpass")
	resp, err := client.Ask(socket, broker.Request{Op: "status", Check: *check})
	if err != nil {
		return err
	}
	st := resp.Status
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	var failed []string
	fmt.Printf("broker:   running at %s\n", socket)
	line := func(name string, c *broker.CredStatus, describe func(*broker.CredStatus) string) {
		switch {
		case c == nil:
			fmt.Printf("%-9s none\n", name+":")
		case c.Problem != "":
			fmt.Printf("%-9s BROKEN: %s\n", name+":", c.Problem)
			failed = append(failed, name)
		case c.CheckError != "":
			fmt.Printf("%-9s %s\n          check FAILED: %s\n", name+":", describe(c), c.CheckError)
			failed = append(failed, name)
		default:
			fmt.Printf("%-9s %s\n", name+":", describe(c))
		}
	}
	line("token", st.Token, func(c *broker.CredStatus) string {
		s := fmt.Sprintf("%s for %s", map[string]string{"pat": "classic PAT", "login": "device login"}[c.Source], c.Login)
		if !c.Expires.IsZero() {
			days := int(time.Until(c.Expires).Hours() / 24)
			s += fmt.Sprintf(", expires %s (%d days)", c.Expires.Format("2006-01-02"), days)
			if days < 14 {
				s += ". Renew it soon: sudo " + system.Binary + " install-pat"
			}
		} else if !c.Created.IsZero() {
			days := int(time.Since(c.Created).Hours() / 24)
			s += fmt.Sprintf(", %d days old, doesn't expire", days)
			if days > 90 {
				s += ". Consider renewing: sudo " + system.Binary + " login"
			}
		}
		return s
	})
	line("ssh", st.SSH, func(c *broker.CredStatus) string {
		if c.Login != "" {
			return c.Public + "\n          GitHub accepts it for " + c.Login
		}
		return c.Public
	})
	line("signing", st.Signing, func(c *broker.CredStatus) string { return c.Public })
	if len(st.Repos) == 0 {
		fmt.Printf("repos:    none allowed yet. Add some: sudo %s allow OWNER/REPO\n", system.Binary)
	} else {
		fmt.Printf("repos:    %s\n", strings.Join(st.Repos, ", "))
	}
	if st.Policy != "" {
		fmt.Printf("policy:   %s\n", st.Policy)
	}
	fmt.Printf("audit:    %s\n", system.LogHint())
	if len(failed) > 0 {
		return fmt.Errorf("not working: %s", strings.Join(failed, ", "))
	}
	return nil
}
