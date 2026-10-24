package mt19937

// State holds the 624 words of the 32-bit Mersenne Twister. This generator
// reproduces an existing protocol; it must not be used as a source of secrets.
type State [624]uint32

func (s *State) Seed(seed uint32) {
	s[0] = seed
	for i := 1; i < len(s); i++ {
		previous := s[i-1]
		s[i] = 1812433253*(previous^(previous>>30)) + uint32(i)
	}
}

func (s *State) Twist() {
	for i := 0; i < 227; i++ {
		s[i] = twist(s[i], s[i+1], s[i+397])
	}
	for i := 227; i < len(s)-1; i++ {
		s[i] = twist(s[i], s[i+1], s[i-227])
	}
	s[623] = twist(s[623], s[0], s[396])
}

func twist(current, next, distant uint32) uint32 {
	joined := current&0x80000000 | next&0x7fffffff
	value := distant ^ joined>>1
	if joined&1 != 0 {
		value ^= 0x9908b0df
	}
	return value
}

func Temper(value uint32) uint32 {
	value ^= value >> 11
	value ^= value << 7 & 0x9d2c5680
	value ^= value << 15 & 0xefc60000
	return value ^ value>>18
}
