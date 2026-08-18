package store

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// ULID generation without an external dependency. A ULID is a 128-bit,
// lexicographically-sortable identifier: 48 bits of millisecond timestamp
// followed by 80 bits of randomness, rendered in Crockford base32 (26 chars).
// Sortable IDs mean findings naturally order by creation time in the store and
// UI without a separate timestamp index (decision #1: ULID over UUIDv4).

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID builds a ULID for time t using cryptographically random entropy.
func NewULID(t time.Time) (string, error) {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	// 48-bit timestamp, big-endian, in the first 6 bytes.
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	if _, err := rand.Read(b[6:]); err != nil {
		return "", err
	}
	return encodeCrockford(b), nil
}

// encodeCrockford renders 16 bytes as 26 Crockford-base32 characters.
func encodeCrockford(b [16]byte) string {
	// Treat the 128 bits as a big integer and emit 26 base32 symbols.
	// We build from the most-significant end so the string sorts like the bytes.
	out := make([]byte, 26)
	// Split into high and low 64-bit words for shifting.
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&0x1f]
		// shift the 128-bit value right by 5, carrying from hi into lo.
		lo = (lo >> 5) | (hi << 59)
		hi >>= 5
	}
	return string(out)
}
