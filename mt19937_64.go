package main

const N = 312
const M = 156
const MATRIX_A = 0xB5026F5AA96619E9
const UPPER_MASK = 0xFFFFFFFF80000000
const LOWER_MASK = 0x7FFFFFFF

type MT19937_64 struct {
	array [312]uint64 //state vector
	index uint64      // array index
}

func New() *MT19937_64 {
	return &MT19937_64{
		index: N + 1,
	}
}

func (m *MT19937_64) Seed(seed int64) {
	m.array[0] = uint64(seed)
	for m.index = 1; m.index < N; m.index++ {
		m.array[m.index] = (6364136223846793005*(m.array[m.index-1]^(m.array[m.index-1]>>62)) + m.index)
	}
}

func (m *MT19937_64) Generate() int64 {
	return m.Int63()
}

func (m *MT19937_64) Int63() int64 {
	var i int
	var x uint64
	mag01 := []uint64{0, MATRIX_A}
	if m.index >= N {
		/* Initialize with a default Seed if Seed() not previously called */
		if m.index == N+1 {
			m.Seed(int64(5489))
		}

		for i = 0; i < N-M; i++ {
			x = (m.array[i] & UPPER_MASK) | (m.array[i+1] & LOWER_MASK)
			m.array[i] = m.array[i+(M)] ^ (x >> 1) ^ mag01[int(x&uint64(1))]
		}
		for ; i < N-1; i++ {
			x = (m.array[i] & UPPER_MASK) | (m.array[i+1] & LOWER_MASK)
			m.array[i] = m.array[i+(M-N)] ^ (x >> 1) ^ mag01[int(x&uint64(1))]
		}
		x = (m.array[N-1] & UPPER_MASK) | (m.array[0] & LOWER_MASK)
		m.array[N-1] = m.array[M-1] ^ (x >> 1) ^ mag01[int(x&uint64(1))]
		m.index = 0

	}
	x = m.array[m.index]
	m.index++
	x ^= (x >> 29) & 0x5555555555555555
	x ^= (x << 17) & 0x71D67FFFEDA60000
	x ^= (x << 37) & 0xFFF7EEE000000000
	x ^= (x >> 43)

	return int64(x)
}
