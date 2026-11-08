//go:build !darwin

package keys

import "errors"

// The sealed backend is macOS-only. Linux seals to the TPM where there is
// one, and uses the file backend otherwise.
func haveSealed() bool { return false }

func machineFingerprint() ([]byte, error) {
	return nil, errors.New("the sealed backend is only available on macOS")
}
