package system

import (
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// LogHint tells the user how to read the audit log.
func LogHint() string { return "sudo " + Binary + " log" }

// openLogFiles reads the log at path and the copies newsyslog rotated out of
// it, oldest first: path.4.gz, ..., path.0.gz, then path. A copy may be
// compressed or not. A missing path is fine if there are rotated copies.
func openLogFiles(path string) (io.ReadCloser, error) {
	matches, err := filepath.Glob(path + ".*")
	if err != nil {
		return nil, err
	}
	type rotated struct {
		n    int
		path string
	}
	var old []rotated
	for _, m := range matches {
		suffix := strings.TrimSuffix(strings.TrimPrefix(m, path+"."), ".gz")
		if n, err := strconv.Atoi(suffix); err == nil && n >= 0 {
			old = append(old, rotated{n, m})
		}
	}
	slices.SortFunc(old, func(a, b rotated) int { return b.n - a.n })

	ml := &multiLog{}
	for _, o := range old {
		if err := ml.add(o.path); err != nil {
			_ = ml.Close()
			return nil, err
		}
	}
	if err := ml.add(path); err != nil && (!errors.Is(err, os.ErrNotExist) || len(old) == 0) {
		_ = ml.Close()
		return nil, err
	}
	ml.r = io.MultiReader(ml.readers...)
	return ml, nil
}

// multiLog reads several log files as one, with a newline between them in
// case one doesn't end with one.
type multiLog struct {
	r       io.Reader
	readers []io.Reader
	closers []io.Closer
}

func (m *multiLog) add(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	m.closers = append(m.closers, f)
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return errors.New(path + ": " + err.Error())
		}
		r = gz
	}
	m.readers = append(m.readers, r, strings.NewReader("\n"))
	return nil
}

func (m *multiLog) Read(p []byte) (int, error) { return m.r.Read(p) }

func (m *multiLog) Close() error {
	var errs []error
	for _, c := range m.closers {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}
