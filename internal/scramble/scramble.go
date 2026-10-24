package scramble

import "encoding/binary"

// Bytes masks each byte by its position and seed, then permutes eight-byte
// words with a deterministic Sattolo shuffle. The length must be divisible by
// eight, with at most 2^32-1 words. All arithmetic wraps at its stated width.
// This is the recovered table representation transform, not a general cipher.
func Bytes(data []byte, seed uint32) {
	if len(data)%8 != 0 || uint64(len(data)/8) > uint64(^uint32(0)) {
		panic("scramble: invalid buffer length")
	}
	key := byte(seed)
	square := key * key
	for i, value := range data {
		position := byte(i)
		data[i] = (value ^ key ^ (position*position - square)) * 0x93
	}
	for i := len(data)/8 - 1; i > 0; i-- {
		j := int(((seed + uint32(i)) ^ seed) * 0x1000193 % uint32(i))
		a := binary.LittleEndian.Uint64(data[i*8:])
		b := binary.LittleEndian.Uint64(data[j*8:])
		binary.LittleEndian.PutUint64(data[i*8:], b)
		binary.LittleEndian.PutUint64(data[j*8:], a)
	}
}
