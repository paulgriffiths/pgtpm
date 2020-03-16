package pgtpm

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
)

// KDFa implements the KDFa function per the TPM2.0 spec.
func KDFa(h func() hash.Hash, key []byte, label string, context []byte, numbytes int) ([]byte, error) {
	var fixed = append([]byte(label), 0x00)
	fixed = append(fixed, context...)

	var lcount = make([]byte, 4)
	binary.BigEndian.PutUint32(lcount, uint32(numbytes)*8)
	fixed = append(fixed, lcount...)

	return kdfCounter(h, key, nil, fixed, uint32(numbytes), 4)
}

// kdfCounter implements a key derivation function in counter mode, as defined
// by NIST SP 800-108. Fixed data may be place before or after the counter, or
// both. l is the number of requested bytes, and r is the size, in bytes, of
// the counter. Only HMAC-based PRFs are supported.
func kdfCounter(h func() hash.Hash, key, before, after []byte, l, r uint32) ([]byte, error) {

	// r must be <= 32 bits, per SP800-108 section 5.
	if r < 1 || r > 4 {
		return nil, fmt.Errorf("r must be 1, 2, 3 or 4 bytes")
	}

	// Calculate number of iterations required.
	var hashSize = uint32(h().Size())
	var n = l / hashSize
	if l%hashSize != 0 {
		n++
	}

	// Number of iterations shall not exceed (2^r)-1, per SP800-108 section 5.
	// Since this function accepts L and r in bytes, we multiply r by 8.
	if uint64(n) > ((2 ^ uint64(r)*8) - 1) {
		return nil, fmt.Errorf("l too large")
	}

	// Perform PRF iterations.
	var out = make([]byte, 0, n*hashSize)
	var cbuf = make([]byte, 4)
	for c := uint32(1); c <= uint32(n); c++ {
		binary.BigEndian.PutUint32(cbuf, c)

		var mac = hmac.New(h, key)
		mac.Write(before)
		mac.Write(cbuf[4-r : 4])
		mac.Write(after)

		out = append(out, mac.Sum(nil)...)
	}

	// Return only the requested number of bytes.
	return out[:l], nil
}
