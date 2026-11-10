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
	if err := system.RequireRoot("log"); err != nil {
		return err
	}
	src, err := system.OpenLog(f.Since)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(os.Stdout)
	err = printLog(w, src, f, *summary, time.Local)
	err = errors.Join(err, w.Flush(), src.Close())
	return err
}

// printLog renders the records in src that f picks.
func printLog(w io.Writer, src io.Reader, f audit.Filter, summary bool, loc *time.Location) error {
	var records []audit.Record
	var werr error
	n := 0
	lines, err := audit.Scan(src, f, func(r audit.Record) {
		n++
		if summary {
			records = append(records, r)
		} else if werr == nil {
			_, werr = fmt.Fprintln(w, audit.Line(r, loc))
		}
	})
	if err = errors.Join(err, werr); err != nil {
		return err
	}
	if summary {
		return audit.WriteSummary(w, audit.Summarize(records), loc)
	}
	if n == 0 {
		fmt.Fprintf(os.Stderr, "Nothing matched, out of %d lines in the log.\n", lines)
	}
	return nil
}
