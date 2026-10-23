package applemusic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
)

// DecryptSPD decodes GrandSlam's encrypted JSON account dictionary using the
// minimally encoded SRP key returned by VerifyServerProof. It implements the
// native AES operation, not the complete authenticated response protocol: the
// separate np field and its relationship to this data are still under research.
// CBC decryption alone does not establish integrity. Do not treat the returned
// dictionary as a completed Apple login or persist its tokens as verified.
func DecryptSPD(key, encrypted []byte) (map[string]json.RawMessage, error) {
	invalid := errors.New("invalid encrypted account data")
	if len(key) == 0 || len(key) > sha256.Size || len(encrypted) == 0 ||
		len(encrypted) > maxResponseBytes || len(encrypted)%aes.BlockSize != 0 {
		return nil, invalid
	}
	aesKey := deriveSPD(key, "extra data key:")
	iv := deriveSPD(key, "extra data iv:")
	defer clear(aesKey)
	defer clear(iv)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, invalid
	}
	plain := make([]byte, len(encrypted))
	defer clear(plain)
	cipher.NewCBCDecrypter(block, iv[:aes.BlockSize]).CryptBlocks(plain, encrypted)
	// Java's AES/CBC/PKCS5Padding uses PKCS#7 padding for AES's 16-byte block.
	padding := int(plain[len(plain)-1])
	valid := subtle.ConstantTimeLessOrEq(1, padding) & subtle.ConstantTimeLessOrEq(padding, aes.BlockSize)
	for i := 1; i <= aes.BlockSize; i++ {
		within := subtle.ConstantTimeLessOrEq(i, padding)
		equal := subtle.ConstantTimeByteEq(plain[len(plain)-i], byte(padding))
		valid &= (1 - within) | equal
	}
	if valid != 1 {
		return nil, invalid
	}
	var account map[string]json.RawMessage
	if err := json.Unmarshal(plain[:len(plain)-padding], &account); err != nil || account == nil {
		return nil, invalid
	}
	return account, nil
}

func deriveSPD(key []byte, label string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(label))
	return h.Sum(nil)
}
