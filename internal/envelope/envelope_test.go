package envelope

import (
	"bytes"
	"testing"
)

func TestPortableExportBoundsAndCorruption(t *testing.T) {
	plain := bytes.Repeat([]byte("fixture"), 1024)
	blob, err := Encode("TEST0001", plain, 8192)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode("TEST0001", blob, 8192)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("round trip failed", err)
	}
	bad := bytes.Clone(blob)
	bad[20] ^= 1
	for _, data := range [][]byte{nil, blob[:len(blob)-1], bad, append(bytes.Clone(blob), 0), append(bytes.Clone(blob), blob[40:]...)} {
		if data, err := Decode("TEST0001", data, 8192); err == nil || data != nil {
			t.Fatal("corrupt, truncated or trailing data accepted")
		}
	}
	if _, err := Decode("TEST0002", blob, 8192); err == nil {
		t.Fatal("wrong type accepted")
	}
	if _, err := Decode("TEST0001", blob, 1024); err == nil {
		t.Fatal("decompression limit ignored")
	}
}
