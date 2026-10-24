package montgomery

// NegativeInverse returns -1/a modulo 2^32. The word must be odd.
// Each Newton step doubles the number of correct bits, starting from one bit.
func NegativeInverse(a uint32) uint32 {
	if a&1 == 0 {
		panic("montgomery: inverse requires an odd word")
	}
	x := uint32(1)
	for range 5 {
		x *= 2 - a*x
	}
	return -x
}

// Square writes a²/R modulo modulus, where R = 2^(32*len(modulus)).
// Words are little-endian. The result is unreduced and may be >= modulus;
// dst has len(modulus)+1 words to retain the final carry. The input must fit
// len(modulus) words, and inverse*modulus[0] must be -1 modulo 2^32.
// dst must not overlap the input or modulus. Loop counts depend only on lengths.
func Square(dst, a, modulus []uint32, inverse uint32) {
	Multiply(dst, a, a, modulus, inverse)
}

// Multiply writes a*b/R modulo modulus with the same word order, unreduced
// output and destination-aliasing requirements as Square. Both operands may
// have fewer words than modulus; missing words are zero.
//
// The return value is the low word of the final product column before reduction.
// The temporary runtime adapter retains it for instruction-boundary equivalence;
// mathematical callers can ignore it.
func Multiply(dst, a, b, modulus []uint32, inverse uint32) uint32 {
	n := len(modulus)
	if n == 0 || len(dst) != n+1 || len(a) > n || len(b) > n || inverse*modulus[0] != ^uint32(0) {
		panic("montgomery: invalid operands")
	}
	clear(dst)
	var lastColumn uint32
	for i := 0; i < n; i++ {
		var multiplier uint32
		if i < len(b) {
			multiplier = b[i]
		}
		product := uint64(dst[0])
		if len(a) != 0 {
			product += uint64(multiplier) * uint64(a[0])
		}
		correction := uint32(product) * inverse
		reduced := uint64(uint32(product)) + uint64(correction)*uint64(modulus[0])
		for j := 1; j < n; j++ {
			product = uint64(dst[j]) + product>>32
			if j < len(a) {
				product += uint64(multiplier) * uint64(a[j])
			}
			reduced = uint64(uint32(product)) + reduced>>32 + uint64(correction)*uint64(modulus[j])
			dst[j-1] = uint32(reduced)
		}
		lastColumn = uint32(product)
		carry := uint64(dst[n]) + product>>32 + reduced>>32
		dst[n-1], dst[n] = uint32(carry), uint32(carry>>32)
	}
	return lastColumn
}

// PutBytes writes little-endian words in big-endian byte order, applying mask
// to each output byte. It truncates high bytes or pads with zeros to fill dst.
// dst and words must not overlap.
func PutBytes(dst []byte, words []uint32, mask byte) {
	for i := range dst {
		var word uint32
		if i/4 < len(words) {
			word = words[i/4]
		}
		dst[len(dst)-1-i] = byte(word>>uint(i%4*8)) ^ mask
	}
}

// SetBytes fills little-endian words from big-endian src, subtracting bias from
// each byte modulo 256. It truncates high bytes or pads with zero words to fill
// dst. The byte adjustment happens before padding. dst and src must not overlap.
func SetBytes(dst []uint32, src []byte, bias byte) {
	clear(dst)
	for i := 0; i < len(src) && i/4 < len(dst); i++ {
		dst[i/4] |= uint32(src[len(src)-1-i]-bias) << uint(i%4*8)
	}
}
