package system

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// followWriter writes the broker's log to the file at path, and follows the
// path when something rotates it. newsyslog renames the log and puts a new
// file in its place without telling the broker, so before each write it
// checks whether the file at path is still the one it has open, and reopens
// the path when it isn't. Until a new file is at path it keeps writing to the
// old one, unless it may create the file itself.
//
// Each Write is one call to the file, under a lock, so concurrent log lines
// don't interleave.
type followWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
	// create is whether the writer may create path. It does only when it
	// owns the directory: in someone else's, such as root's /var/log, the
	// file's owner and mode are whoever rotates it to decide.
	create bool
	// replace puts newf where f was and returns the file to write to from
	// then on. The default closes f and returns newf.
	replace func(f, newf *os.File) (*os.File, error)
}

// newFollowWriter follows path, starting with f, which should be open on it.
func newFollowWriter(path string, f *os.File) *followWriter {
	w := &followWriter{path: path, f: f, replace: func(f, newf *os.File) (*os.File, error) {
		_ = f.Close()
		return newf, nil
	}}
	if fi, err := os.Stat(filepath.Dir(path)); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) == os.Geteuid() {
			w.create = true
		}
	}
	return w
}

func (w *followWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.follow()
	return w.f.Write(p)
}

// follow reopens path if the file there isn't the one w has open. Any
// failure leaves w writing where it was, and the next write tries again.
func (w *followWriter) follow() {
	cur, err := w.f.Stat()
	if err != nil {
		return
	}
	at, err := os.Stat(w.path)
	if err == nil && os.SameFile(cur, at) {
		return
	}
	if err != nil && (!os.IsNotExist(err) || !w.create) {
		return
	}
	flags := os.O_APPEND | os.O_WRONLY
	if w.create {
		flags |= os.O_CREATE
	}
	newf, err := os.OpenFile(w.path, flags, 0o640) //nolint:gosec // the broker's own user and group read the audit log; nobody else can
	if err != nil {
		return
	}
	f, err := w.replace(w.f, newf)
	if err != nil {
		_ = newf.Close()
		return
	}
	w.f = f
}
