package policy

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"strings"
	"testing"
	"time"
)

// packEntry is one object for buildPack: a whole object (typ 1-3), an
// offset delta against an earlier entry (typ 6), or a ref delta (typ 7).
type packEntry struct {
	typ   byte
	data  []byte // content, or delta instructions
	ofs   int    // for typ 6: index of the base entry
	base  string // for typ 7: base object ID
	claim int    // if set, the size the header declares instead of len(data)
}

// buildPack writes entries as a version 2 pack with its trailer.
func buildPack(t *testing.T, entries []packEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(len(entries)))
	offs := make([]int, len(entries))
	for i, e := range entries {
		offs[i] = b.Len()
		size := len(e.data)
		if e.claim != 0 {
			size = e.claim
		}
		hdr := []byte{e.typ<<4 | byte(size&0x0f)}
		size >>= 4
		for size > 0 {
			hdr[len(hdr)-1] |= 0x80
			hdr = append(hdr, byte(size&0x7f))
			size >>= 7
		}
		b.Write(hdr)
		switch e.typ {
		case 6:
			// Offset back to the base, in git's offset encoding.
			d := offs[i] - offs[e.ofs]
			enc := []byte{byte(d & 0x7f)}
			for d >>= 7; d > 0; d >>= 7 {
				d--
				enc = append([]byte{0x80 | byte(d&0x7f)}, enc...)
			}
			b.Write(enc)
		case 7:
			id, _ := hex.DecodeString(e.base)
			b.Write(id)
		}
		zw := zlib.NewWriter(&b)
		zw.Write(e.data)
		zw.Close()
	}
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes()
}

func varint(n int) []byte {
	var out []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, c)
		}
		out = append(out, c|0x80)
	}
}

// appendOne is a delta that copies all of a base of size n and adds "x".
func appendOne(n int) []byte {
	d := append(varint(n), varint(n+1)...)
	for off := 0; off < n; off += 0x10000 {
		chunk := min(n-off, 0x10000)
		d = append(d, 0x80|0x0f|0x30, byte(off), byte(off>>8), byte(off>>16), byte(off>>24), byte(chunk), byte(chunk>>8))
	}
	return append(d, 1, 'x')
}

func readFast(t *testing.T, raw []byte) (*Pack, error) {
	t.Helper()
	start := time.Now()
	p, err := ReadPack(bytes.NewReader(raw))
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("ReadPack took %v", d)
	}
	return p, err
}

// A small pack whose deltas each expand to megabytes is refused once the
// expansion passes maxTotal, not held in memory.
func TestReadPackRefusesDeltaExpansion(t *testing.T) {
	base := bytes.Repeat([]byte("a"), 0x10000)
	// Each delta copies the whole base 120 times: about 7.5 MB out from a
	// few hundred bytes in.
	const copies = 120
	delta := append(varint(len(base)), varint(copies*len(base))...)
	delta = append(delta, bytes.Repeat([]byte{0x80}, copies)...)
	entries := []packEntry{{typ: 3, data: base}}
	for range maxTotal/(copies*len(base)) + 2 {
		entries = append(entries, packEntry{typ: 6, data: delta, ofs: 0})
	}
	raw := buildPack(t, entries)
	if len(raw) > 64<<10 {
		t.Fatalf("test pack is %d bytes, meant to be small", len(raw))
	}
	if _, err := readFast(t, raw); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("ReadPack = %v, want a too-large refusal", err)
	}
}

// An object too large to keep is still read to its declared size, and one
// that inflates past its declared size is refused.
func TestReadPackBigObjectSize(t *testing.T) {
	big := bytes.Repeat([]byte("b"), maxKept+1)
	if _, err := readFast(t, buildPack(t, []packEntry{{typ: 3, data: big}})); err != nil {
		t.Errorf("ReadPack of a big blob = %v, want nil", err)
	}
	// Declares maxKept+1 bytes and inflates to 64 MB.
	bomb := packEntry{typ: 3, data: bytes.Repeat([]byte("b"), 64<<20), claim: maxKept + 1}
	if _, err := readFast(t, buildPack(t, []packEntry{bomb})); err == nil {
		t.Error("ReadPack accepted an object that inflates past its header")
	}
}

// An offset-delta chain deeper than git ever writes still resolves, in
// order, without deep recursion.
func TestReadPackResolvesDeepChain(t *testing.T) {
	const n = 5000
	entries := []packEntry{{typ: 3, data: []byte("a")}}
	for i := range n {
		entries = append(entries, packEntry{typ: 6, data: appendOne(i + 1), ofs: i})
	}
	p, err := readFast(t, buildPack(t, entries))
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("no pack")
	}
}

// Ref deltas whose bases come later in the pack resolve, and quickly, even
// in reverse order.
func TestReadPackResolvesReversedRefDeltas(t *testing.T) {
	const n = 3000
	content := []byte("a")
	ids := []string{objectID("blob", content)}
	chain := []packEntry{{typ: 3, data: content}}
	for i := range n {
		chain = append(chain, packEntry{typ: 7, data: appendOne(len(content)), base: ids[i]})
		content = append(bytes.Clone(content), 'x')
		ids = append(ids, objectID("blob", content))
	}
	// Each delta before its base.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	if _, err := readFast(t, buildPack(t, chain)); err != nil {
		t.Fatalf("reversed ref deltas: %v", err)
	}
}

// A long offset-delta chain on a ref delta whose base comes last resolves in
// one pass. Walking the chain down to the missing base for every entry took
// time quadratic in its length.
func TestReadPackResolvesChainOnLateBase(t *testing.T) {
	const n = 20000
	// Each delta turns a one-byte object into another, so the work is in
	// the visits, not the data.
	x := []byte{1, 1, 1, 'x'}
	entries := []packEntry{{typ: 7, data: x, base: objectID("blob", []byte("a"))}}
	for i := range n {
		entries = append(entries, packEntry{typ: 6, data: x, ofs: i})
	}
	entries = append(entries, packEntry{typ: 3, data: []byte("a")})
	if _, err := readFast(t, buildPack(t, entries)); err != nil {
		t.Fatal(err)
	}
}

// A header that claims millions of objects costs nothing until they arrive.
func TestReadPackIgnoresClaimedCount(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(9_999_999))
	allocs := testing.AllocsPerRun(5, func() { ReadPack(bytes.NewReader(b.Bytes())) })
	if allocs > 50 {
		t.Errorf("a 12-byte pack header cost %.0f allocations", allocs)
	}
	var m1, m2 runtimeMem
	m1.read()
	ReadPack(bytes.NewReader(b.Bytes()))
	m2.read()
	if grew := m2.total - m1.total; grew > 8<<20 {
		t.Errorf("a 12-byte pack header allocated %d bytes", grew)
	}
}

type runtimeMem struct{ total uint64 }

func (m *runtimeMem) read() {
	var s runtime.MemStats
	runtime.ReadMemStats(&s)
	m.total = s.TotalAlloc
}

// Every object counts against maxInflated by the size it declares, before
// any of it inflates, including blobs too big to keep. So a pack can't make
// the broker inflate more than that, however well its blobs compress.
func TestReadPackChargesDeclaredSize(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(1))
	// A blob that says it's one byte over the budget.
	size := uint64(maxInflated) + 1
	hdr := []byte{3<<4 | byte(size&0x0f) | 0x80}
	for size >>= 4; size > 0; size >>= 7 {
		c := byte(size & 0x7f)
		if size > 0x7f {
			c |= 0x80
		}
		hdr = append(hdr, c)
	}
	b.Write(hdr)
	zw := zlib.NewWriter(&b)
	zw.Write([]byte("x"))
	zw.Close()
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	if _, err := readFast(t, b.Bytes()); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("ReadPack = %v, want a too-large refusal", err)
	}
}
