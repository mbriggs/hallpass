package keys

import (
	"bytes"
	"testing"
)

// The real fingerprint must read every input, and read the same each time,
// or credentials stop opening.
func TestMachineFingerprintIsStable(t *testing.T) {
	a, err := machineFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	b, err := machineFingerprint()
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("second read differs: %v", err)
	}
	for _, key := range []string{"IOPlatformSerialNumber", "IOPlatformUUID", "VolumeUUID"} {
		if !bytes.Contains(a, []byte(key)) {
			t.Errorf("fingerprint lacks %s", key)
		}
	}
}
