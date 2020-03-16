package pgtpm

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestKDFCounter(t *testing.T) {
	t.Parallel()

	// Read test data from file.

	var f, err = os.Open("testdata/kdf_counter.txt")
	if err != nil {
		t.Fatalf("couldn't open test file: %v", err)
	}
	defer f.Close()

	type testcase struct {
		name     string
		hashfunc func() hash.Hash
		ctrLoc   string
		count    int
		rlen     uint32
		l        uint32
		key      []byte
		before   []byte
		after    []byte
		want     []byte
	}

	var r = csv.NewReader(f)
	r.Comment = '#'
	r.FieldsPerRecord = 9

	var testcases []testcase

recordLoop:
	for {
		var record, err = r.Read()
		if err != nil {
			switch err {
			case io.EOF:
				break recordLoop

			default:
				t.Fatalf("couldn't read CSV record: %v", err)
			}
		}

		var tc testcase

		switch record[0] {
		case "hmac_sha1":
			tc.hashfunc = sha1.New

		case "hmac_sha224":
			tc.hashfunc = sha256.New224

		case "hmac_sha256":
			tc.hashfunc = sha256.New

		case "hmac_sha284":
			tc.hashfunc = sha512.New384

		case "hmac_sha512":
			tc.hashfunc = sha512.New

		default:
			t.Fatalf("unsupported hash function: %s", record[0])
		}

		tc.ctrLoc = record[1]

		tc.count, err = strconv.Atoi(record[2])
		if err != nil {
			t.Fatalf("couldn't convert count %q to integer", record[2])
		}

		var n uint64
		n, err = strconv.ParseUint(record[3], 10, 32)
		if err != nil {
			t.Fatalf("couldn't convert RLEN %q to integer", record[3])
		}
		tc.rlen = uint32(n)

		n, err = strconv.ParseUint(record[4], 10, 32)
		if err != nil {
			t.Fatalf("couldn't convert L %q to integer", record[4])
		}
		tc.l = uint32(n)

		tc.key = mustDecodeHexString(t, record[5])
		tc.before = mustDecodeHexString(t, record[6])
		tc.after = mustDecodeHexString(t, record[7])
		tc.want = mustDecodeHexString(t, record[8])

		tc.name = fmt.Sprintf("%s/%s/RLEN=%d/L=%d/COUNT=%d", strings.ToUpper(record[0]),
			strings.ToUpper(tc.ctrLoc), tc.rlen, tc.l, tc.count)

		testcases = append(testcases, tc)
	}

	// Perform tests.

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = kdfCounter(tc.hashfunc, tc.key, tc.before, tc.after, tc.l, tc.rlen)
			if err != nil {
				t.Fatalf("couldn't derive key: %v", err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func mustDecodeHexString(t *testing.T, s string) []byte {
	t.Helper()

	var result, err = hex.DecodeString(s)
	if err != nil {
		t.Fatalf("couldn't decode hex string: %v", err)
	}

	return result
}
