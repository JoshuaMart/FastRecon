// Package runid generates ULID-style identifiers for a run: a millisecond
// timestamp followed by randomness, so ids sort chronologically as strings.
package runid

import (
	"crypto/rand"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New builds a 26-character identifier from t plus 80 bits of randomness.
func New(t time.Time) string {
	var buf [16]byte
	ms := uint64(t.UTC().UnixMilli())
	for i := 0; i < 6; i++ {
		buf[5-i] = byte(ms >> (8 * i))
	}
	// crypto/rand.Read never returns an error; it panics on a broken source.
	_, _ = rand.Read(buf[6:])
	return encode(buf[:])
}

// encode renders 128 bits as 26 base32 characters, left-padded to 130 bits.
func encode(b []byte) string {
	out := make([]byte, 26)
	for i := range out {
		var v uint
		for j := 0; j < 5; j++ {
			v = v<<1 | bitAt(b, i*5+j)
		}
		out[i] = crockford[v]
	}
	return string(out)
}

// bitAt reads bit p of the padded stream: two zero bits, then b.
func bitAt(b []byte, p int) uint {
	if p < 2 {
		return 0
	}
	q := p - 2
	return uint(b[q/8]>>(7-uint(q%8))) & 1
}
