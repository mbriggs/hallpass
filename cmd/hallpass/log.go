package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mbriggs/hallpass/internal/audit"
	"github.com/mbriggs/hallpass/internal/github"
	"github.com/mbriggs/hallpass/internal/system"
	"golang.org/x/term"
)

// logCmd prints the audit log, a line per request, or with --summary, the
// refusals counted by repo and reason. It needs root, as reading the journal
// or /var/log/hallpass.log does.
func logCmd(args []string) error {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	refused := fs.Bool("refused", false, "show only refusals")
	repo := fs.String("repo", "", "show only requests for `OWNER/REPO`")
	since := fs.String("since", "", "show only what came after `WHEN`: 2h, 3d, 2026-11-01, or \"2026-11-01 14:00\"")
	summary := fs.Bool("summary", false, "count the refusals by repo and reason")
	all := fs.Bool("all", false, "show every line as logged, routine status checks included, with no folding")
	color := fs.String("color", "auto", "color the output: `WHEN` is auto (when stdout is a terminal and NO_COLOR isn't set), always, or never")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: sudo %s log [flags]\n%s\n\nflags:\n", system.Binary, logHelp)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("log takes no arguments, only flags; try --repo %s", fs.Arg(0))
	}
	f := audit.Filter{Refused: *refused || *summary}
	if *repo != "" {
		r, err := github.ParseRepo(*repo)
		if err != nil {
			return err
		}
		f.Repo = r.String()
	}
	if *since != "" {
		t, err := audit.ParseSince(*since, time.Now())
		if err != nil {
			return err
		}
		f.Since = t
	}
	on, err := useColor(*color, term.IsTerminal(int(os.Stdout.Fd())), os.Getenv)
	if err != nil {
		return err
	}
	if err := system.RequireRoot("log"); err != nil {
		return err
	}
	src, err := system.OpenLog(f.Since)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(os.Stdout)
	v := audit.View{Loc: time.Local, Color: on}
	err = printLog(w, src, f, logOpts{view: v, summary: *summary, all: *all})
	err = errors.Join(err, w.Flush(), src.Close())
	return err
}

// logHelp is the first line of log's help, here and in the usage.
const logHelp = "Prints what agents asked for and what was refused. Routine status checks are hidden; --all shows them."

// useColor decides whether to color the output. sudo's env_reset keeps TERM
// but drops NO_COLOR unless sudoers lets the caller set it, so --color
// never is the way that works under any sudoers.
func useColor(when string, tty bool, getenv func(string) string) (bool, error) {
	switch when {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "auto":
		return tty && getenv("NO_COLOR") == "" && getenv("TERM") != "dumb", nil
	}
	return false, fmt.Errorf("--color takes auto, always, or never, not %q", when)
}

type logOpts struct {
	view    audit.View
	summary bool
	all     bool
}

// printLog renders the records in src that f picks.
func printLog(w io.Writer, src io.Reader, f audit.Filter, o logOpts) error {
	var records []audit.Record
	var werr error
	p := audit.NewPrinter(w, o.view, o.all)
	lines, err := audit.Scan(src, f, func(r audit.Record) {
		if o.summary {
			records = append(records, r)
		} else if werr == nil {
			werr = p.Add(r)
		}
	})
	if werr == nil {
		werr = p.Flush()
	}
	if err = errors.Join(err, werr); err != nil {
		return err
	}
	if o.summary {
		return o.view.WriteSummary(w, audit.Summarize(records))
	}
	switch shown, hidden := p.Counts(); {
	case shown == 0 && hidden > 0:
		fmt.Fprintf(os.Stderr, "Nothing to show but %d routine status checks; --all shows them.\n", hidden)
	case shown == 0:
		fmt.Fprintf(os.Stderr, "Nothing matched, out of %d lines in the log.\n", lines)
	}
	return nil
}
