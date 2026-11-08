//go:build !linux

package keys

import (
	"crypto"
	"errors"
)

var errNoTPM = errors.New("the tpm backend is only available on Linux")

func haveTPM() bool                         { return false }
func createTPM(string) ([]byte, error)      { return nil, errNoTPM }
func loadTPM(string) (crypto.Signer, error) { return nil, errNoTPM }
func sealTPM([]byte) ([]byte, error)        { return nil, errNoTPM }
func unsealTPM(string) ([]byte, error)      { return nil, errNoTPM }
