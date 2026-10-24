package montgomery

// Square writes a²/R modulo modulus, where R = 2^(32*len(modulus)).
// Words are little-endian. The result is unreduced and may be >= modulus;
// dst has len(modulus)+1 words to retain the final carry. The input must fit
// len(modulus) words, and inverse*modulus[0] must be -1 modulo 2^32.
// The slices must not overlap. Loop counts depend only on operand lengths.
func Square(dst, a, modulus []uint32, inverse uint32) {
	n := len(modulus)
	if n == 0 || len(dst) != n+1 || len(a) > n || inverse*modulus[0] != ^uint32(0) {
		panic("montgomery: invalid square operands")
	}
	clear(dst)
	for i := 0; i < n; i++ {
		var multiplier uint32
		if i < len(a) {
			multiplier = a[i]
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
		carry := uint64(dst[n]) + product>>32 + reduced>>32
		dst[n-1], dst[n] = uint32(carry), uint32(carry>>32)
	}
}
