// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package subtle_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/tink/go/tink"
)

var (
	ikm = []byte{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb,
		0xc, 0xd, 0xe, 0xf, 0x0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	aad = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
)

// encrypt generates a random plaintext of size plaintextSize and encrypts it
// using the cipher. Upon success this function returns the actual plaintext
// and ciphertext bytes.
func encrypt(cipher tink.StreamingAEAD, aad []byte, plaintextSize int) ([]byte, []byte, error) {
	pt := make([]byte, plaintextSize)
	for i := range pt {
		pt[i] = byte(i % 253)
	}

	ctBuf := &bytes.Buffer{}
	w, err := cipher.NewEncryptingWriter(ctBuf, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create an encrypt writer: %v", err)
	}
	n, err := w.Write(pt)
	if err != nil {
		return nil, nil, fmt.Errorf("error writing to an encrypt writer: %v", err)
	}
	if n != len(pt) {
		return nil, nil, fmt.Errorf("unexpected number of bytes written. Got=%d;want=%d", n, len(pt))
	}
	if err := w.Close(); err != nil {
		return nil, nil, fmt.Errorf("error closing writer: %v", err)
	}
	return pt, ctBuf.Bytes(), err
}

// decrypt decrypts ciphertext ct using the cipher and validates that it's the
// same as the original plaintext pt.
func decrypt(cipher tink.StreamingAEAD, aad, pt, ct []byte, chunkSize int) error {
	r, err := cipher.NewDecryptingReader(bytes.NewBuffer(ct), aad)
	if err != nil {
		return fmt.Errorf("cannot create an encrypt reader: %v", err)
	}

	var (
		chunk     = make([]byte, chunkSize)
		decrypted = 0
		eof       = false
	)
	for !eof {
		n, err := r.Read(chunk)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading chunk: %v", err)
		}
		eof = err == io.EOF
		got := chunk[:n]
		want := pt[decrypted : decrypted+n]
		if !bytes.Equal(got, want) {
			return fmt.Errorf("decrypted data doesn't match. Got=%s;want=%s", hex.EncodeToString(got), hex.EncodeToString(want))
		}
		decrypted += n
	}
	if decrypted != len(pt) {
		return fmt.Errorf("number of decrypted bytes doesn't match. Got=%d;want=%d", decrypted, len(pt))
	}
	return nil
}

func segmentPos(segmentSize, firstSegmentOffset, headerLen, segmentNr int) (int, int) {
	start := segmentSize * segmentNr
	end := start + segmentSize

	firstSegmentDiff := firstSegmentOffset + headerLen
	if start > 0 {
		start -= firstSegmentDiff
	}
	end -= firstSegmentDiff
	return start + headerLen, end + headerLen
}
