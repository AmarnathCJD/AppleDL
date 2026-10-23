package standalone

import (
	"encoding/binary"
	"strings"
	"time"
)

// Virtual paths never reach the host filesystem. Persistence is a separate,
// encrypted snapshot of this bounded map, owned by one local device instance.
type virtualFiles struct {
	data     map[string][]byte
	dirs     map[string]bool
	modified map[string]int64 // Unix nanoseconds, persisted with native bytes
	open     map[uint64]*virtualFD
	next     uint64
	dirty    bool
}

type virtualFD struct {
	name   string
	offset uint64
	flags  uint64
}

func newVirtualFiles() *virtualFiles {
	return &virtualFiles{data: map[string][]byte{}, dirs: map[string]bool{"/adi": true}, modified: map[string]int64{}, open: map[uint64]*virtualFD{}, next: 10}
}

func (f *virtualFiles) touch(name string) {
	f.modified[name] = max(time.Now().UnixNano(), f.modified[name]+1)
	f.dirty = true
}

func validVirtualPath(name string) bool {
	if len(name) > 4096 || strings.ContainsAny(name, "\x00\\") {
		return false
	}
	if name == "/adi" {
		return true
	}
	if !strings.HasPrefix(name, "/adi/") {
		return false
	}
	for _, part := range strings.Split(name[5:], "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (f *virtualFiles) openFile(name string, flags uint64) (uint64, int) {
	if !validVirtualPath(name) {
		return 0, 13
	}
	if f.dirs[name] {
		return 0, 21
	}
	if len(f.open) >= 128 {
		return 0, 24
	}
	if flags & ^uint64(3|64|128|512|1024|0x8000|0x80000) != 0 || flags&3 == 3 {
		return 0, 22
	}
	_, exists := f.data[name]
	if !exists {
		if flags&64 == 0 {
			return 0, 2
		}
		if !f.dirs[name[:strings.LastIndexByte(name, '/')]] || len(f.data) >= 128 {
			return 0, 2
		}
		f.data[name] = []byte{}
		f.touch(name)
	} else if flags&192 == 192 {
		return 0, 17
	}
	if flags&512 != 0 {
		if flags&3 == 0 {
			return 0, 22
		}
		clear(f.data[name])
		f.data[name] = []byte{}
		f.touch(name)
	}
	fd := f.next
	f.next++
	f.open[fd] = &virtualFD{name: name, flags: flags}
	return fd, 0
}

func (f *virtualFiles) readFile(fd, size uint64) ([]byte, int) {
	h, ok := f.open[fd]
	if !ok || h.flags&3 == 1 {
		return nil, 9
	}
	if size > 4<<20 {
		return nil, 22
	}
	data := f.data[h.name]
	start := min(h.offset, uint64(len(data)))
	end := min(start+size, uint64(len(data)))
	h.offset = end
	return append([]byte(nil), data[start:end]...), 0
}

func (f *virtualFiles) resize(name string, size uint64) int {
	if size > 4<<20 {
		return 27
	}
	old := f.data[name]
	total := int(size)
	for key, value := range f.data {
		if key != name {
			total += len(value)
		}
	}
	if total > 16<<20 {
		return 28
	}
	data := make([]byte, size)
	copy(data, old)
	clear(old)
	f.data[name] = data
	f.touch(name)
	return 0
}

func (f *virtualFiles) writeFile(fd uint64, data []byte) (uint64, int) {
	h, ok := f.open[fd]
	if !ok || h.flags&3 == 0 {
		return 0, 9
	}
	if h.flags&1024 != 0 {
		h.offset = uint64(len(f.data[h.name]))
	}
	end := h.offset + uint64(len(data))
	if end < h.offset || end > 4<<20 {
		return 0, 27
	}
	if end > uint64(len(f.data[h.name])) {
		if code := f.resize(h.name, end); code != 0 {
			return 0, code
		}
	}
	copy(f.data[h.name][h.offset:], data)
	h.offset = end
	f.touch(h.name)
	return uint64(len(data)), 0
}

func (f *virtualFiles) stat(name string) ([]byte, int) {
	if !validVirtualPath(name) {
		return nil, 13
	}
	data, file := f.data[name]
	if !file && !f.dirs[name] {
		return nil, 2
	}
	// Android bionic aarch64 struct stat: mode+16, size+48, blksize+56,
	// blocks+64; signed time fields start at 72. No host struct is copied.
	raw := make([]byte, 128)
	binary.LittleEndian.PutUint64(raw[8:], 1)
	mode := uint32(0x8000 | 0o600)
	if !file {
		mode = 0x4000 | 0o700
	}
	binary.LittleEndian.PutUint32(raw[16:], mode)
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint64(raw[48:], uint64(len(data)))
	binary.LittleEndian.PutUint32(raw[56:], 4096)
	binary.LittleEndian.PutUint64(raw[64:], uint64((len(data)+511)/512))
	// CoreADI uses st_mtime to decide whether to load its on-disk cache. Zero
	// collides with its initial cache sentinel and skips reading a saved device.
	stamp := f.modified[name]
	if stamp <= 0 {
		stamp = int64(time.Second)
	} // stable directory fallback
	for _, offset := range []int{72, 88, 104} {
		binary.LittleEndian.PutUint64(raw[offset:], uint64(stamp/int64(time.Second)))
		binary.LittleEndian.PutUint64(raw[offset+8:], uint64(stamp%int64(time.Second)))
	}
	return raw, 0
}
