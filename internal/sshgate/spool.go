package sshgate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// MaxSpool bounds the bytes of every pack the spool holds at once, so
// clients opening many pushes can't fill the disk. It fits four packs of
// maxPack.
const MaxSpool = 4 * maxPack

// maxPack bounds one pushed pack.
const maxPack = 512 << 20

var (
	errSpoolFull = errors.New("the broker is holding too many pushes; try again")
	errPackLarge = fmt.Errorf("this push's pack is over hallpass's %d MB limit", maxPack>>20)
)

// Spool holds pushed packs on disk while the gate checks them, so a pack
// waits in a file instead of in the broker's memory. Each file is unlinked as
// soon as it's made, so it has no name anyone can open, and the kernel frees
// it when the gate closes it or the broker exits.
type Spool struct {
	dir  string
	max  int64
	mu   sync.Mutex
	used int64
}

// OpenSpool makes dir, readable only by the broker user, and removes any
// pack a crash left there between making a file and unlinking it. max
// bounds the bytes held across all pushes.
func OpenSpool(dir string, limit int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs x to be entered, and only the broker user gets it
		return nil, err
	}
	left, _ := filepath.Glob(filepath.Join(dir, "pack-*"))
	for _, f := range left {
		if err := os.Remove(f); err != nil {
			return nil, err
		}
	}
	return &Spool{dir: dir, max: limit}, nil
}

// spooled is one push's pack on disk. Release it on every path; that
// returns its bytes to the spool's budget.
type spooled struct {
	f *os.File
	s *Spool
	n int64
}

// take copies r, the rest of a push after its commands, into a new spool
// file, up to EOF. git closes its side once it has sent the pack. It fails
// once the push passes maxPack or the spool's budget, and on any read error,
// such as the client going away.
func (s *Spool) take(r io.Reader) (*spooled, error) {
	if s == nil {
		return nil, errors.New("the broker has nowhere to hold this push")
	}
	f, err := os.CreateTemp(s.dir, "pack-*")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	sp := &spooled{f: f, s: s}
	if _, err := io.Copy(sp, io.LimitReader(r, maxPack+1)); err != nil {
		sp.release()
		return nil, err
	}
	if sp.n > maxPack {
		sp.release()
		return nil, errPackLarge
	}
	if err := sp.rewind(); err != nil {
		sp.release()
		return nil, err
	}
	return sp, nil
}

// Write charges p to the spool's budget before it writes p.
func (sp *spooled) Write(p []byte) (int, error) {
	s := sp.s
	s.mu.Lock()
	if s.used+int64(len(p)) > s.max {
		s.mu.Unlock()
		return 0, errSpoolFull
	}
	s.used += int64(len(p))
	s.mu.Unlock()
	sp.n += int64(len(p))
	return sp.f.Write(p)
}

func (sp *spooled) Read(p []byte) (int, error) { return sp.f.Read(p) }

// rewind moves back to the start of the pack, to read it again.
func (sp *spooled) rewind() error {
	_, err := sp.f.Seek(0, io.SeekStart)
	return err
}

// release closes the file, which frees it, and returns its bytes to the
// budget. A second call does nothing.
func (sp *spooled) release() {
	sp.s.mu.Lock()
	sp.s.used -= sp.n
	sp.s.mu.Unlock()
	sp.n = 0
	_ = sp.f.Close()
}
