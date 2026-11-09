package sshgate

import (
	"bytes"
	"testing"
)

// A ref list or refusal bigger than one frame reaches the wrapper whole,
// in frames it accepts.
func TestFrameSplitsLargeData(t *testing.T) {
	var buf bytes.Buffer
	o := &out{w: &buf}
	data := bytes.Repeat([]byte("x"), 2<<20+1)
	if err := o.frame(FrameStdout, data); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for buf.Len() > 0 {
		kind, p, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame after %d bytes: %v", len(got), err)
		}
		if kind != FrameStdout {
			t.Fatalf("frame kind %d", kind)
		}
		got = append(got, p...)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("read %d bytes, wrote %d", len(got), len(data))
	}
}
