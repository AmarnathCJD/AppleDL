package standalone

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const stateMagic = "AMST0001"

// stateKey is local protection, not an OS credential vault. The directory and
// key file permissions protect it; copying the directory copies access too.
// Callers serialize changes under the device lock.
func stateKey(dir string, create bool) ([]byte, error) {
	path := filepath.Join(dir, "state.key")
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		key, err := io.ReadAll(io.LimitReader(f, 33))
		if err != nil || len(key) != 32 {
			clear(key)
			return nil, errors.New("invalid local state key")
		}
		return key, nil
	}
	if !os.IsNotExist(err) || !create {
		return nil, errors.New("local state key unavailable")
	}
	// Refuse to regenerate a key for existing encrypted state.
	for _, name := range []string{"device.state", "idms.state", "commerce.state"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return nil, errors.New("state key missing; existing encrypted state was preserved")
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		clear(key)
		return nil, errors.New("cannot create local state key")
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		clear(key)
		_ = os.Remove(path)
		return nil, errors.New("cannot save local state key")
	}
	return key, nil
}

func protectState(dir, kind string, input []byte, decrypt bool) ([]byte, error) {
	invalid := errors.New("invalid or unreadable protected state")
	if len(input) == 0 || len(input) > stateLimit {
		return nil, invalid
	}
	key, err := stateKey(dir, !decrypt)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, invalid
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, invalid
	}
	header := []byte(stateMagic)
	aad := []byte(stateMagic + ":" + kind)
	if decrypt {
		if len(input) < len(header)+gcm.NonceSize()+gcm.Overhead() || string(input[:len(header)]) != stateMagic {
			return nil, invalid
		}
		nonce := input[len(header) : len(header)+gcm.NonceSize()]
		plain, err := gcm.Open(nil, nonce, input[len(header)+len(nonce):], aad)
		if err != nil {
			return nil, invalid
		}
		return plain, nil
	}
	if len(input) > stateLimit-len(header)-gcm.NonceSize()-gcm.Overhead() {
		return nil, invalid
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(append(header, nonce...), nonce, input, aad), nil
}
