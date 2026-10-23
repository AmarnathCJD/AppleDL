package standalone

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

func (v *goVM) errno(code int) uint64 {
	v.write(v.reg(regTLS)+0x100, binary.LittleEndian.AppendUint32(nil, uint32(code)))
	return ^uint64(0)
}

func (v *goVM) importCall(name string, a [8]uint64) (uint64, error) {
	switch name {
	case "__cxa_atexit", "__cxa_finalize", "__register_atfork", "dlclose":
		return 0, nil // Calls within an engine are serialized by the Go owner.
	case "pthread_create":
		return v.createThread(a)
	case "pthread_rwlock_init", "pthread_rwlock_destroy", "pthread_rwlock_rdlock", "pthread_rwlock_wrlock", "pthread_rwlock_unlock":
		return v.rwlock(name, a)
	case "sleep":
		v.currentThread.wake = time.Now().Add(time.Duration(uint32(a[0])) * time.Second)
		v.yieldThread = true
		return 0, nil
	case "dlopen":
		parts := strings.Split(string(v.cstr(a[0], 4096)), "/")
		if parts[len(parts)-1] == "libCoreLSKD.so" && v.libraries["libCoreLSKD.so"] == 0x40000000 {
			return 0x40000000, nil
		}
		if parts[len(parts)-1] == "libCoreFP.so" && v.exports["X46O5IeS"] != 0 {
			return 0x30000000, nil
		}
		if parts[len(parts)-1] != "libCoreADI.so" {
			return 0, errors.New("unavailable library")
		}
		return 0x10000000, nil
	case "dlsym":
		symbol := string(v.cstr(a[1], 4096))
		if a[0] == 0x40000000 && v.libraries["libCoreLSKD.so"] == a[0] {
			if address := v.exports[symbol]; address >= 0x40000000 && address < 0x50000000 {
				return address, nil
			}
			return 0, errors.New("unavailable playback symbol")
		}
		if a[0] == 0x30000000 {
			if address := v.exports[symbol]; address >= 0x30000000 && address < 0x40000000 {
				return address, nil
			}
			return 0, errors.New("unavailable FairPlay symbol")
		}
		if a[0] != 0x10000000 || (symbol != "cvu8io98wun" && symbol != "vdfut768ig") {
			return 0, errors.New("unavailable symbol")
		}
		return v.exports[symbol], nil
	case "malloc":
		return v.alloc(a[0]), nil
	case "calloc":
		if a[0] > bufferLimit || a[1] > bufferLimit || a[0]*a[1] > bufferLimit {
			return 0, errors.New("allocation bound")
		}
		return v.alloc(a[0] * a[1]), nil
	case "free":
		v.free(a[0])
		return 0, nil
	case "memcpy", "memmove":
		v.write(a[0], v.read(a[1], a[2]))
		return a[0], nil
	case "memset":
		if a[2] > bufferLimit {
			return 0, errors.New("memory bound")
		}
		v.write(a[0], bytes.Repeat([]byte{byte(a[1])}, int(a[2])))
		return a[0], nil
	case "memcmp":
		return uint64(int64(bytes.Compare(v.read(a[0], a[2]), v.read(a[1], a[2])))), nil
	case "strlen":
		return uint64(len(v.cstr(a[0], 4096))), nil
	case "strcmp", "strncmp":
		limit := uint64(4096)
		if name == "strncmp" {
			limit = a[2]
		}
		return uint64(int64(bytes.Compare(v.cstr(a[0], limit), v.cstr(a[1], limit)))), nil
	case "strcpy", "strncpy":
		limit := uint64(4096)
		if name == "strncpy" {
			limit = a[2]
		}
		source := v.cstr(a[1], limit)
		var data []byte
		if name == "strncpy" {
			data = make([]byte, limit)
			copy(data, source)
		} else {
			data = append(source, 0)
		}
		v.write(a[0], data)
		return a[0], nil
	case "__errno":
		return v.reg(regTLS) + 0x100, nil
	case "getauxval":
		if a[0] == 6 {
			return 4096, nil
		}
		if a[0] == 16 || a[0] == 26 {
			return 0, nil
		}
		return 0, errors.New("unsupported auxiliary vector")
	case "__system_property_get":
		value := v.systemProperties[string(v.cstr(a[0], 92))]
		if len(value) >= 92 || strings.ContainsRune(value, 0) {
			return 0, errors.New("invalid native system property")
		}
		v.write(a[1], append([]byte(value), 0))
		return uint64(len(value)), nil
	case "arc4random":
		var raw [4]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, errors.New("native entropy unavailable")
		}
		return uint64(binary.LittleEndian.Uint32(raw[:])), nil
	case "gettimeofday":
		now := time.Now()
		raw := binary.LittleEndian.AppendUint64(nil, uint64(now.Unix()))
		raw = binary.LittleEndian.AppendUint64(raw, uint64(now.Nanosecond()/1000))
		v.write(a[0], raw)
		if a[1] != 0 {
			v.write(a[1], make([]byte, 8))
		}
		return 0, nil
	case "umask":
		return 0o077, nil
	case "open":
		fd, code := v.files.openFile(string(v.cstr(a[0], 4096)), a[1])
		if code != 0 {
			return v.errno(code), nil
		}
		return fd, nil
	case "read":
		data, code := v.files.readFile(a[0], a[2])
		if code != 0 {
			return v.errno(code), nil
		}
		v.write(a[1], data)
		return uint64(len(data)), nil
	case "write":
		size, code := v.files.writeFile(a[0], v.read(a[1], a[2]))
		if code != 0 {
			return v.errno(code), nil
		}
		return size, nil
	case "close":
		if _, ok := v.files.open[a[0]]; !ok {
			return v.errno(9), nil
		}
		delete(v.files.open, a[0])
		return 0, nil
	case "lstat", "fstat":
		var path string
		if name == "lstat" {
			path = string(v.cstr(a[0], 4096))
		} else {
			h, ok := v.files.open[a[0]]
			if !ok {
				return v.errno(9), nil
			}
			path = h.name
		}
		data, code := v.files.stat(path)
		if code != 0 {
			return v.errno(code), nil
		}
		v.write(a[1], data)
		return 0, nil
	case "ftruncate":
		h, ok := v.files.open[a[0]]
		if !ok || h.flags&3 == 0 {
			return v.errno(9), nil
		}
		if code := v.files.resize(h.name, a[1]); code != 0 {
			return v.errno(code), nil
		}
		return 0, nil
	case "chmod":
		_, code := v.files.stat(string(v.cstr(a[0], 4096)))
		if code != 0 {
			return v.errno(code), nil
		}
		return 0, nil
	case "mkdir":
		path := string(v.cstr(a[0], 4096))
		if !validVirtualPath(path) {
			return v.errno(13), nil
		}
		if _, exists := v.files.stat(path); exists == 0 {
			return v.errno(17), nil
		}
		if len(v.files.dirs) >= 128 || !v.files.dirs[path[:strings.LastIndexByte(path, '/')]] {
			return v.errno(2), nil
		}
		v.files.dirs[path] = true
		v.files.dirty = true
		return 0, nil
	}
	return 0, errors.New("unsupported native import")
}
