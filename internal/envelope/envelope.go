// Package envelope encodes portable private exports with bounded decompression
// and a corruption checksum. It does not encrypt or authenticate their contents.
// Anyone holding an export can use it; callers must treat it as a secret.
package envelope

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io"
)

func Encode(kind string, plain []byte, limit int) ([]byte, error) {
	if len(kind) != 8 || len(plain) == 0 || len(plain) > limit {
		return nil, errors.New("invalid export size or type")
	}
	var b bytes.Buffer
	b.WriteString(kind)
	sum := sha256.Sum256(plain)
	b.Write(sum[:])
	z := gzip.NewWriter(&b)
	if _, err := z.Write(plain); err != nil {
		return nil, err
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	if b.Len() > limit {
		return nil, errors.New("export exceeds size limit")
	}
	return b.Bytes(), nil
}

func Decode(kind string, blob []byte, limit int) ([]byte, error) {
	invalid := errors.New("invalid or corrupt portable export")
	if len(kind) != 8 || len(blob) <= 40 || len(blob) > limit || string(blob[:8]) != kind {
		return nil, invalid
	}
	b := bytes.NewReader(blob[40:])
	z, err := gzip.NewReader(b)
	if err != nil {
		return nil, invalid
	}
	z.Multistream(false)
	plain, err := io.ReadAll(io.LimitReader(z, int64(limit)+1))
	closeErr := z.Close()
	sum := sha256.Sum256(plain)
	if err != nil || closeErr != nil || b.Len() != 0 || len(plain) == 0 || len(plain) > limit || !bytes.Equal(sum[:], blob[8:40]) {
		clear(plain)
		return nil, invalid
	}
	return plain, nil
}
