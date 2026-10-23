package applemusic

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

type PasswordScheme string

const (
	S2K   PasswordScheme = "s2k"
	S2KFO PasswordScheme = "s2k_fo"
	// Bound server-controlled work. This is a client limit, not an Apple constant.
	MaxPasswordIterations = 1_000_000
)

// DerivePassword implements the password transform at libAMSKit 0x64bc4c.
// It is input to SRP, not a password token or a complete sign-in operation.
func DerivePassword(password string, salt []byte, iterations int, scheme PasswordScheme) ([]byte, error) {
	if password == "" || len(salt) == 0 || len(salt) > 1024 {
		return nil, errors.New("password and salt of 1 to 1024 bytes are required")
	}
	if iterations < 1 || iterations > MaxPasswordIterations {
		return nil, errors.New("password iteration count outside client limits")
	}
	digest := sha256.Sum256([]byte(password))
	input := string(digest[:])
	switch scheme {
	case S2K:
	case S2KFO:
		input = hex.EncodeToString(digest[:])
	default:
		return nil, errors.New("unsupported password scheme")
	}
	return pbkdf2.Key(sha256.New, input, salt, iterations, 32)
}
