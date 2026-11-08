package keys

import (
	"bytes"
	"crypto"
	"fmt"
	"os"
	"sync"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const tpmDevice = "/dev/tpmrm0"

// openTPM is swapped for a simulator in tests.
var openTPM = func() (transport.TPMCloser, error) { return linuxtpm.Open(tpmDevice) }

func haveTPM() bool {
	_, err := os.Stat(tpmDevice)
	return err == nil
}

// The broker keeps one TPM connection for its lifetime and shares it between
// keys.
var (
	sharedMu  sync.Mutex
	sharedTPM transport.TPMCloser
)

func tpmConn() (transport.TPMCloser, error) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedTPM == nil {
		t, err := openTPM()
		if err != nil {
			return nil, fmt.Errorf("opening TPM: %w", err)
		}
		sharedTPM = t
	}
	return sharedTPM, nil
}

// createTPM generates a P-256 key under the TPM's storage root key. The
// private part leaves the TPM only wrapped to that key.
func createTPM(description string) ([]byte, error) {
	tpm, err := tpmConn()
	if err != nil {
		return nil, err
	}
	k, err := keyfile.NewLoadableKey(tpm, tpm2.TPMAlgECC, 256, nil, keyfile.WithDescription(description))
	if err != nil {
		return nil, fmt.Errorf("creating key in TPM: %w", err)
	}
	return encode(k)
}

func loadTPM(path string) (crypto.Signer, error) {
	k, err := decode(path)
	if err != nil {
		return nil, err
	}
	tpm, err := tpmConn()
	if err != nil {
		return nil, err
	}
	return k.Signer(tpm, nil, nil)
}

func sealTPM(secret []byte) ([]byte, error) {
	tpm, err := tpmConn()
	if err != nil {
		return nil, err
	}
	k, err := keyfile.NewSealedData(tpm, secret, nil, keyfile.WithDescription("hallpass GitHub token"))
	if err != nil {
		return nil, fmt.Errorf("sealing to TPM: %w", err)
	}
	return encode(k)
}

func unsealTPM(path string) ([]byte, error) {
	k, err := decode(path)
	if err != nil {
		return nil, err
	}
	tpm, err := tpmConn()
	if err != nil {
		return nil, err
	}
	// keyfile.UnsealData leaves the sealed object and its parent loaded.
	// The kernel's resource manager allows three objects per connection,
	// and the broker keeps its connection, so flush both here.
	sess := keyfile.NewTPMSession(tpm)
	defer sess.FlushHandle()
	item, parent, err := keyfile.LoadKey(sess, k, nil)
	if parent != nil {
		defer keyfile.FlushHandle(tpm, *parent)
	}
	if err != nil {
		return nil, err
	}
	defer keyfile.FlushHandle(tpm, *item)
	rsp, err := tpm2.Unseal{ItemHandle: item}.Execute(sess.GetTPM(), sess.GetHMACOut())
	if err != nil {
		return nil, fmt.Errorf("unsealing: %w", err)
	}
	return rsp.OutData.Buffer, nil
}

func encode(k *keyfile.TPMKey) ([]byte, error) {
	var buf bytes.Buffer
	if err := keyfile.Encode(&buf, k); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decode(path string) (*keyfile.TPMKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := keyfile.Decode(b)
	if err != nil {
		return nil, fmt.Errorf("decoding TPM blob %s: %w", path, err)
	}
	return k, nil
}
