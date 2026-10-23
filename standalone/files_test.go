package standalone

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestVirtualFilesBoundaries(t *testing.T) {
	f := newVirtualFiles()
	for _, name := range []string{"/outside", "/adi/../escape", "/adi/a/../../b", "/adi\\x", "/adi/", "/adi//x", "/adi/x\x00y"} {
		if _, code := f.openFile(name, 66); code == 0 {
			t.Fatal("accepted outside or ambiguous path")
		}
	}
	if _, code := f.openFile("/adi/missing", 0); code != 2 {
		t.Fatal("missing file not reported")
	}
	fd, code := f.openFile("/adi/data", 66)
	if code != 0 {
		t.Fatal(code)
	}
	if _, code = f.writeFile(fd, []byte("abc")); code != 0 {
		t.Fatal(code)
	}
	if code = f.resize("/adi/data", 1); code != 0 {
		t.Fatal(code)
	}
	if code = f.resize("/adi/data", 3); code != 0 {
		t.Fatal(code)
	}
	rd, code := f.openFile("/adi/data", 0)
	if code != 0 {
		t.Fatal(code)
	}
	data, code := f.readFile(rd, 10)
	if code != 0 || !bytes.Equal(data, []byte{'a', 0, 0}) {
		t.Fatal("truncate did not discard old bytes")
	}
	if _, code := f.writeFile(rd, []byte("x")); code != 9 {
		t.Fatal("wrote through read-only descriptor")
	}
	stat, code := f.stat("/adi/data")
	if code != 0 || binary.LittleEndian.Uint64(stat[48:]) != 3 || binary.LittleEndian.Uint32(stat[16:]) != 0x8180 {
		t.Fatal("incorrect bionic file stat")
	}
	if binary.LittleEndian.Uint64(stat[88:]) == 0 || binary.LittleEndian.Uint64(stat[96:]) >= 1_000_000_000 {
		t.Fatal("mtime must be nonzero and use the bionic timespec layout")
	}
	stamp := f.modified["/adi/data"]
	if _, code := f.writeFile(fd, []byte("x")); code != 0 || f.modified["/adi/data"] <= stamp {
		t.Fatal("write did not update file modification time")
	}
	// Restore the boundary fixture after the metadata check.
	if code := f.resize("/adi/data", 3); code != 0 {
		t.Fatal(code)
	}
	if code := f.resize("/adi/data", (4<<20)+1); code == 0 {
		t.Fatal("accepted oversized file")
	}
	appendFD, code := f.openFile("/adi/data", 1025)
	if code != 0 {
		t.Fatal(code)
	}
	if _, code := f.writeFile(appendFD, []byte("z")); code != 0 || !bytes.Equal(f.data["/adi/data"], []byte{'a', 0, 0, 'z'}) {
		t.Fatal("append failed")
	}
	if _, code := f.openFile("/adi/data", 64|128|2); code != 17 {
		t.Fatal("exclusive creation replaced a file")
	}
}
