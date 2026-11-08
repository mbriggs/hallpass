package policy

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha1" //nolint:gosec // git object IDs are SHA-1; this checks them, it doesn't protect anything with them
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Pack is the commits and trees in a git packfile, with their IDs. The
// workflow check never needs blob contents, so blobs are read only to
// resolve deltas and then dropped.
type Pack struct {
	Objects map[string]Object
	// Size is how many bytes the pack took, trailer included.
	Size int64
}

// Object is a commit or tree.
type Object struct {
	Type string // "commit" or "tree"
	Data []byte
}

// maxKept bounds the inflated size of one object the reader keeps, and
// maxTotal all of them. maxInflated bounds every object the reader
// inflates, kept or not, so a small pack of highly compressed blobs can't
// make it inflate without end. A push that needs more can't be checked, so
// it's refused.
const (
	maxKept     = 8 << 20
	maxTotal    = 1 << 30
	maxInflated = 4 << 30
)

type rawObject struct {
	typ  byte
	data []byte // inflated: content, or delta instructions
	base string // ref-delta base ID
	ofs  int64  // base offset, absolute; a ref-delta gets it when its base resolves
	big  bool   // too large to keep
}

type countingReader struct {
	r *bufio.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.n++
	}
	return b, err
}

// ReadPack reads a packfile from r, stopping right after its trailer, so a
// stream may continue after it.
func ReadPack(r io.Reader) (*Pack, error) {
	cr := &countingReader{r: bufio.NewReaderSize(r, 64<<10)}
	h := sha1.New() //nolint:gosec // git object IDs are SHA-1
	var hdr [12]byte
	if _, err := io.ReadFull(cr, hdr[:]); err != nil {
		return nil, errorf("truncated pack")
	}
	h.Write(hdr[:])
	if string(hdr[:4]) != "PACK" {
		return nil, errorf("not a pack")
	}
	if v := binary.BigEndian.Uint32(hdr[4:8]); v != 2 && v != 3 {
		return nil, errorf("pack version %d", v)
	}
	count := binary.BigEndian.Uint32(hdr[8:12])
	if count > 10_000_000 {
		return nil, errorf("pack has too many objects")
	}

	raws := map[int64]*rawObject{}
	// The header's count is the sender's claim, so don't size anything by it.
	order := make([]int64, 0, min(count, 1<<12))
	total := 0
	inflate := uint64(maxInflated)
	for range count {
		off := cr.n
		obj, err := readEntry(cr, h, off, &inflate)
		if err != nil {
			return nil, err
		}
		if total += len(obj.data); total > maxTotal {
			return nil, errorf("this push is too large for hallpass to check")
		}
		raws[off] = obj
		order = append(order, off)
	}
	var trailer [20]byte
	if _, err := io.ReadFull(cr, trailer[:]); err != nil {
		return nil, errorf("truncated pack")
	}
	if !bytes.Equal(h.Sum(nil), trailer[:]) {
		return nil, errorf("pack checksum doesn't match")
	}

	p := &Pack{Objects: map[string]Object{}, Size: cr.n}
	// Resolve each object once, after its base: whole objects first, then
	// each delta when the object it builds on resolves. An offset delta
	// waits on its base's offset, a ref-delta on its base's ID. A crafted
	// order, like a ref-delta whose base comes last under a long chain of
	// offset deltas, then costs one visit per object, not one per link.
	onOffset := map[int64][]int64{}
	onID := map[string][]int64{}
	var ready []int64
	for _, off := range order {
		switch o := raws[off]; o.typ {
		case 6:
			if raws[o.ofs] == nil {
				return nil, errorf("pack delta points outside the pack")
			}
			onOffset[o.ofs] = append(onOffset[o.ofs], off)
		case 7:
			onID[o.base] = append(onID[o.base], off)
		default:
			ready = append(ready, off)
		}
	}
	resolved := map[int64]resolvedObject{}
	for len(ready) > 0 {
		off := ready[len(ready)-1]
		ready = ready[:len(ready)-1]
		ro, err := resolve(raws[off], resolved)
		if err != nil {
			return nil, err
		}
		// Deltas expand to new data, which counts against the same bound
		// as the entries, so a small pack can't make the broker hold a lot.
		if t := raws[off].typ; t == 6 || t == 7 {
			if total += len(ro.data); total > maxTotal {
				return nil, errorf("this push is too large for hallpass to check")
			}
		}
		resolved[off] = ro
		ready = append(ready, onOffset[off]...)
		delete(onOffset, off)
		if ro.known {
			if ro.typ == "commit" || ro.typ == "tree" {
				p.Objects[ro.id] = Object{Type: ro.typ, Data: ro.data}
			}
			for _, d := range onID[ro.id] {
				raws[d].ofs = off
				ready = append(ready, d)
			}
			delete(onID, ro.id)
		}
	}
	if len(resolved) < len(order) {
		return nil, errorf("pack has a delta whose base isn't in the pack")
	}
	return p, nil
}

type resolvedObject struct {
	typ   string
	data  []byte // nil for big objects
	id    string
	known bool // false when the content was too big to keep
}

var typeNames = map[byte]string{1: "commit", 2: "tree", 3: "blob", 4: "tag"}

// resolve returns object o. For a delta, ReadPack has resolved its base,
// at o.ofs, first.
func resolve(o *rawObject, done map[int64]resolvedObject) (resolvedObject, error) {
	if name, ok := typeNames[o.typ]; ok {
		if o.big {
			if name != "blob" {
				return resolvedObject{}, errorf("this push has a %s too large for hallpass to check", name)
			}
			return resolvedObject{typ: name}, nil
		}
		return resolvedObject{typ: name, data: o.data, id: objectID(name, o.data), known: true}, nil
	}
	base := done[o.ofs]
	if o.big || !base.known {
		// Too large to keep. Only a blob gets this big; anything else
		// can't be checked.
		if base.typ != "blob" {
			return resolvedObject{}, errorf("this push has a %s too large for hallpass to check", base.typ)
		}
		return resolvedObject{typ: base.typ}, nil
	}
	data, err := applyDelta(base.data, o.data)
	if err != nil {
		return resolvedObject{}, err
	}
	return resolvedObject{typ: base.typ, data: data, id: objectID(base.typ, data), known: true}, nil
}

func objectID(typ string, data []byte) string {
	h := sha1.New() //nolint:gosec // git object IDs are SHA-1
	fmt.Fprintf(h, "%s %d\x00", typ, len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// readEntry reads one object entry, hashing every byte it consumes, and
// takes its inflated size from the budget at inflate.
func readEntry(cr *countingReader, h io.Writer, off int64, inflate *uint64) (*rawObject, error) {
	tee := &hashingReader{cr: cr, h: h}
	b, err := tee.ReadByte()
	if err != nil {
		return nil, errorf("truncated pack")
	}
	typ := (b >> 4) & 7
	size := uint64(b & 15)
	shift := uint(4)
	for b&0x80 != 0 {
		if b, err = tee.ReadByte(); err != nil {
			return nil, errorf("truncated pack")
		}
		size |= uint64(b&0x7f) << shift
		shift += 7
		if shift > 63 {
			return nil, errorf("malformed pack")
		}
	}
	o := &rawObject{typ: typ}
	switch typ {
	case 1, 2, 3, 4:
	case 6:
		b, err := tee.ReadByte()
		if err != nil {
			return nil, errorf("truncated pack")
		}
		rel := int64(b & 0x7f)
		for b&0x80 != 0 {
			if b, err = tee.ReadByte(); err != nil {
				return nil, errorf("truncated pack")
			}
			rel = ((rel + 1) << 7) | int64(b&0x7f)
		}
		o.ofs = off - rel
		if rel <= 0 || o.ofs < 12 {
			return nil, errorf("malformed pack delta")
		}
	case 7:
		var id [20]byte
		if _, err := io.ReadFull(tee, id[:]); err != nil {
			return nil, errorf("truncated pack")
		}
		o.base = hex.EncodeToString(id[:])
	default:
		return nil, errorf("pack has an object of unknown type %d", typ)
	}
	// The entry declares its size, and nothing reads past it, so charging
	// the declared size bounds the work before any of it is done.
	if size > *inflate {
		return nil, errorf("this push is too large for hallpass to check")
	}
	*inflate -= size
	zr, err := zlib.NewReader(tee)
	if err != nil {
		return nil, errorf("malformed pack data")
	}
	keep := size <= maxKept
	if keep {
		o.data = make([]byte, 0, size)
		buf := bytes.NewBuffer(o.data)
		if _, err := io.Copy(buf, io.LimitReader(zr, int64(size)+1)); err != nil {
			return nil, errorf("malformed pack data")
		}
		o.data = buf.Bytes()
		if uint64(len(o.data)) != size {
			return nil, errorf("pack object size doesn't match")
		}
	} else {
		// Stopping at the declared size means an object can't inflate past
		// what its header claims; the read below catches any excess.
		o.big = true
		n, err := io.Copy(io.Discard, io.LimitReader(zr, int64(size)+1))
		if err != nil || uint64(n) != size { //nolint:gosec // io.Copy never returns a negative count
			return nil, errorf("malformed pack data")
		}
	}
	// Reading to EOF makes zlib check its trailer.
	var one [1]byte
	if n, _ := zr.Read(one[:]); n != 0 {
		return nil, errorf("pack object is longer than it says")
	}
	return o, nil
}

// hashingReader passes reads through to the pack, hashing them for the
// trailer check. It implements io.ByteReader so zlib doesn't read ahead past
// the object.
type hashingReader struct {
	cr *countingReader
	h  io.Writer
}

func (t *hashingReader) Read(p []byte) (int, error) {
	n, err := t.cr.Read(p)
	_, _ = t.h.Write(p[:n])
	return n, err
}

func (t *hashingReader) ReadByte() (byte, error) {
	b, err := t.cr.ReadByte()
	if err == nil {
		_, _ = t.h.Write([]byte{b})
	}
	return b, err
}

func applyDelta(base, delta []byte) ([]byte, error) {
	bad := errors.New("malformed pack delta")
	varint := func() (uint64, error) {
		var v uint64
		var shift uint
		for {
			if len(delta) == 0 || shift > 63 {
				return 0, bad
			}
			b := delta[0]
			delta = delta[1:]
			v |= uint64(b&0x7f) << shift
			shift += 7
			if b&0x80 == 0 {
				return v, nil
			}
		}
	}
	srcSize, err := varint()
	if err != nil || srcSize != uint64(len(base)) {
		return nil, bad
	}
	dstSize, err := varint()
	if err != nil || dstSize > maxKept {
		return nil, bad
	}
	out := make([]byte, 0, dstSize)
	for len(delta) > 0 {
		op := delta[0]
		delta = delta[1:]
		if op&0x80 != 0 {
			var off, n uint64
			for i := range 4 {
				if op&(1<<i) != 0 {
					if len(delta) == 0 {
						return nil, bad
					}
					off |= uint64(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			for i := range 3 {
				if op&(1<<(4+i)) != 0 {
					if len(delta) == 0 {
						return nil, bad
					}
					n |= uint64(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			if n == 0 {
				n = 0x10000
			}
			if off+n > uint64(len(base)) || uint64(len(out))+n > dstSize {
				return nil, bad
			}
			out = append(out, base[off:off+n]...)
		} else if op != 0 {
			if int(op) > len(delta) || uint64(len(out))+uint64(op) > dstSize {
				return nil, bad
			}
			out = append(out, delta[:op]...)
			delta = delta[op:]
		} else {
			return nil, bad
		}
	}
	if uint64(len(out)) != dstSize {
		return nil, bad
	}
	return out, nil
}

// Commit is the part of a commit the workflow check reads.
type Commit struct {
	Tree    string
	Parents []string
}

// ParseCommit reads a commit's tree and parents.
//
// It reads the header the way git does: the first line is the tree, and the
// parent lines follow it directly. git ignores a tree or parent line anywhere
// else, so a commit carrying one is refused rather than read two ways.
func ParseCommit(data []byte) (Commit, error) {
	var c Commit
	head, _, _ := bytes.Cut(data, []byte("\n\n"))
	lines := bytes.Split(head, []byte("\n"))
	tree, ok := bytes.CutPrefix(lines[0], []byte("tree "))
	if !ok || !hexOID.Match(tree) {
		return Commit{}, errorf("malformed commit")
	}
	c.Tree = string(tree)
	i := 1
	for ; i < len(lines); i++ {
		parent, ok := bytes.CutPrefix(lines[i], []byte("parent "))
		if !ok {
			break
		}
		if !hexOID.Match(parent) {
			return Commit{}, errorf("malformed commit")
		}
		c.Parents = append(c.Parents, string(parent))
	}
	for ; i < len(lines); i++ {
		if bytes.HasPrefix(lines[i], []byte("tree ")) || bytes.HasPrefix(lines[i], []byte("parent ")) {
			return Commit{}, errorf("a commit in this push has a tree or parent line where git doesn't read it")
		}
	}
	return c, nil
}

// TreeEntry finds name in a tree object. It returns the entry's mode and ID,
// or "" when the tree has no such entry.
func TreeEntry(data []byte, name string) (mode, id string, err error) {
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		nul := bytes.IndexByte(data, 0)
		if sp < 0 || nul < sp || nul+21 > len(data) {
			return "", "", errorf("malformed tree")
		}
		if string(data[sp+1:nul]) == name {
			return string(data[:sp]), hex.EncodeToString(data[nul+1 : nul+21]), nil
		}
		data = data[nul+21:]
	}
	return "", "", nil
}
