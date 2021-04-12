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

package noncebased_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/google/tink/go/streamingaead/subtle/noncebased"
)

func TestNonceBased(t *testing.T) {

	testcases := []struct {
		name                         string
		plaintextSize                int
		nonceSize                    int
		noncePrefixSize              int
		plaintextSegmentSize         int
		firstCiphertextSegmentOffset int
		chunkSize                    int
	}{
		{
			name:                         "plaintextSizeAlignedWithSegmentSize",
			plaintextSize:                100,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         20,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "plaintextSizeNotAlignedWithSegmentSize",
			plaintextSize:                110,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         20,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "singleSegment",
			plaintextSize:                100,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         100,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "shortPlaintext",
			plaintextSize:                1,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         100,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "shortSegmentSize",
			plaintextSize:                100,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         10,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "largeChunkSize",
			plaintextSize:                100,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         10,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    500,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			writerParams := noncebased.WriterParams{
				NonceSize:                    tc.nonceSize,
				PlaintextSegmentSize:         tc.plaintextSegmentSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			plaintext, ciphertext, noncePrefix, err := testEncrypt(tc.plaintextSize, tc.noncePrefixSize, writerParams)
			if err != nil {
				t.Fatalf("encrypting failed: %v\n", err)
			}

			readerParams := noncebased.ReaderParams{
				NonceSize:                    tc.nonceSize,
				NoncePrefix:                  noncePrefix,
				CiphertextSegmentSize:        tc.plaintextSegmentSize + tc.nonceSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			if err := testDecrypt(plaintext, ciphertext, tc.chunkSize, readerParams); err != nil {
				t.Fatalf("decrypting failed: %v\n", err)
			}
		})
	}
}
func TestNonceBased_invalidParameters(t *testing.T) {

	testcases := []struct {
		name                         string
		plaintextSize                int
		nonceSize                    int
		noncePrefixSize              int
		plaintextSegmentSize         int
		firstCiphertextSegmentOffset int
		chunkSize                    int
		expectedError                error
	}{
		{
			name:                         "nonceTooSmall",
			plaintextSize:                100,
			nonceSize:                    5,
			noncePrefixSize:              5,
			plaintextSegmentSize:         20,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
			expectedError:                noncebased.ErrNonceSizeTooShort,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			writerParams := noncebased.WriterParams{
				NonceSize:                    tc.nonceSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			_, _, _, err := testEncrypt(tc.plaintextSize, tc.noncePrefixSize, writerParams)
			if err != tc.expectedError {
				t.Errorf("did not produce expected error: got: %q, want: %q\n", err, tc.expectedError)
			}

			// Prepare empty input for testDecrypt().
			ciphertextSegmentSize := tc.plaintextSegmentSize + tc.nonceSize

			ciphertextSize := tc.firstCiphertextSegmentOffset
			ciphertextSize += (tc.plaintextSize / tc.plaintextSegmentSize) * ciphertextSegmentSize
			plaintextRemainder := tc.plaintextSize % tc.plaintextSegmentSize
			if plaintextRemainder > 0 {
				ciphertextSize += plaintextRemainder + tc.nonceSize
			}

			readerParams := noncebased.ReaderParams{
				NonceSize:                    tc.nonceSize,
				NoncePrefix:                  make([]byte, tc.noncePrefixSize),
				CiphertextSegmentSize:        tc.plaintextSegmentSize + tc.nonceSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			if err := testDecrypt(make([]byte, tc.plaintextSize), make([]byte, ciphertextSize), tc.chunkSize, readerParams); err != tc.expectedError {
				t.Errorf("did not produce expected error: got: %q, want: %q\n", err, tc.expectedError)
			}
		})
	}
}

// testEncrypter is essentially a no-op cipher.
//
// It produces ciphertexts which contain the plaintext broken into segments,
// with the unmodified per-segment nonce placed at the end of each segment.
type testEncrypter struct {
	noncebased.SegmentEncrypter
}

func (e testEncrypter) EncryptSegment(segment, nonce []byte) ([]byte, error) {
	ctLen := len(segment) + len(nonce)
	ciphertext := make([]byte, ctLen)
	copy(ciphertext, segment)
	copy(ciphertext[len(segment):], nonce)
	return ciphertext, nil
}

type testDecrypter struct {
	noncebased.SegmentDecrypter
}

func (d testDecrypter) DecryptSegment(segment, nonce []byte) ([]byte, error) {
	tagStart := len(segment) - len(nonce)
	if tagStart < 0 {
		return nil, errors.New("segment too short")
	}
	tag := segment[tagStart:]
	if !bytes.Equal(nonce, tag) {
		return nil, fmt.Errorf("tag mismtach:\nsegment: %s\nnonce: %s\ntag: %s", hex.EncodeToString(segment), hex.EncodeToString(nonce), hex.EncodeToString(tag))
	}
	result := make([]byte, tagStart)
	copy(result, segment[:tagStart])
	return result, nil
}

// testEncrypt generates a random plaintext and random noncePrefix, then uses
// them to instantiate a noncebased.Writer and uses it to produce a ciphertext.
//
// The plaintext, ciphertext and nonce prefix are returned.
func testEncrypt(plaintextSize, noncePrefixSize int, wp noncebased.WriterParams) ([]byte, []byte, []byte, error) {
	var dst bytes.Buffer
	dstWriter := bufio.NewWriter(&dst)

	noncePrefix := make([]byte, noncePrefixSize)
	if _, err := rand.Read(noncePrefix); err != nil {
		return nil, nil, nil, err
	}

	wp.W = dstWriter
	wp.SegmentEncrypter = testEncrypter{}
	wp.NoncePrefix = noncePrefix

	w, err := noncebased.NewWriter(wp)
	if err != nil {
		return nil, nil, nil, err
	}

	plaintext := make([]byte, plaintextSize)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, nil, err
	}

	w.Write(plaintext)
	w.Close()
	dstWriter.Flush()
	ciphertext := dst.Bytes()

	return plaintext, ciphertext, noncePrefix, nil
}

// testDecrypt instantiates a noncebased.Reader, uses it to decrypt ciphertext
// and verifies it matches plaintext. While decrypting, it reads in chunkSize
// increments.
func testDecrypt(plaintext, ciphertext []byte, chunkSize int, rp noncebased.ReaderParams) error {
	rp.R = bytes.NewReader(ciphertext)
	rp.SegmentDecrypter = testDecrypter{}
	r, err := noncebased.NewReader(rp)
	if err != nil {
		return err
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
		want := plaintext[decrypted : decrypted+n]
		if !bytes.Equal(got, want) {
			return fmt.Errorf("decrypted data does not match. Got=%s;want=%s", hex.EncodeToString(got), hex.EncodeToString(want))
		}
		decrypted += n
	}
	if decrypted != len(plaintext) {
		return fmt.Errorf("number of decrypted bytes does not match. Got=%d,want=%d", decrypted, len(plaintext))
	}
	return nil
}
