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

// Package noncebased provides a reusable streaming AEAD framework.
//
// It tackles the segment handling portions of the nonce based online
// encryption scheme proposed in "Online Authenticated-Encryption and its
// Nonce-Reuse Misuse-Resistance" by Hoang, Reyhanitabar, Rogaway and Vizár
// (https://eprint.iacr.org/2015/189.pdf).
//
// In this scheme, the format of a ciphertext is:
//
//   header || segment_0 || segment_1 || ... || segment_k.
//
// The format of header is:
//
//   headerLength || salt || nonce_prefix
//
// headerLength is 1 byte which documents the size of the header and can be
// obtained via HeaderLength(). In principle, headerLength is redundant
// information, since the length of the header can be determined from the key
// size.
//
// salt is a salt used in the key derivation.
//
// nonce_prefix is a prefix for all per-segment nonces.
//
// segment_i is the i-th segment of the ciphertext. The size of segment_1 ..
// segment_{k-1} is ciphertextSegmentSize. segment_0 is shorter, so that
// segment_0 plus additional data of size firstCiphertextSegmentOffset (e.g.
// the header) aligns with ciphertextSegmentSize.
//
// The first segment size will be:
//
//		ciphertextSegmentSize - HeaderLength() - firstCiphertextSegmentOffset.
package noncebased

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

var (
	// ErrNonceSizeTooShort indicates that the specified nonce size isn't large
	// enough to hold the nonce prefix, counter and last segment flag.
	ErrNonceSizeTooShort = errors.New("nonce size too short")

	// ErrCiphertextSegmentTooShort indicates the the ciphertext segment being
	// processed is too short.
	ErrCiphertextSegmentTooShort = errors.New("ciphertext segment too short")

	// ErrTooManySegments indicates that the ciphertext has too many segments.
	ErrTooManySegments = errors.New("too many segments")
)

// SegmentEncrypter facilitates implementing various streaming AEAD encryption
// modes.
type SegmentEncrypter interface {
	EncryptSegment(segment, nonce []byte) ([]byte, error)
}

// Writer provides a framework for ingesting plaintext data and
// writing encrypted data to the wrapped io.Writer. The scheme used for
// encrypting segments is specified by providing a SegmentEncrypter
// implementation.
type Writer struct {
	w                            io.Writer
	segmentEncrypter             SegmentEncrypter
	encryptedSegmentCnt          uint64
	firstCiphertextSegmentOffset int
	nonceSize                    int
	noncePrefix                  []byte
	plaintext                    []byte
	plaintextPos                 int
	ciphertext                   []byte
	closed                       bool
}

// WriterParams contains the options for instantiating a Writer via NewWriter().
type WriterParams struct {
	// W is the underlying writer being wrapped.
	W io.Writer

	// SegmentEncrypter provides a method for encrypting segments.
	SegmentEncrypter SegmentEncrypter

	// NonceSize is the length of generated nonces. It must be at least 5 +
	// len(NoncePrefix). It can be longer, but longer nonces introduce more
	// overhead in the resultant ciphertext.
	NonceSize int

	// NoncePrefix is a constant that all nonces throughout the ciphertext will
	// start with. It's length must be at least 5 bytes shorter than NonceSize.
	NoncePrefix []byte

	// The size of the segments which the plaintext will be split into.
	PlaintextSegmentSize int

	// FirstCiphertexSegmentOffset indicates where the ciphertext should begin in
	// W. This allows for the existence of overhead in the stream unrelated to
	// this encryption scheme.
	FirstCiphertextSegmentOffset int
}

// NewWriter creates a new Writer instance.
func NewWriter(params WriterParams) (*Writer, error) {
	if params.NonceSize-len(params.NoncePrefix) < 5 {
		return nil, ErrNonceSizeTooShort
	}
	return &Writer{
		w:                            params.W,
		segmentEncrypter:             params.SegmentEncrypter,
		nonceSize:                    params.NonceSize,
		noncePrefix:                  params.NoncePrefix,
		firstCiphertextSegmentOffset: params.FirstCiphertextSegmentOffset,
		plaintext:                    make([]byte, params.PlaintextSegmentSize),
	}, nil
}

// Write encrypts passed data and passes the encrypted data to the underlying writer.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("write on closed writer")
	}

	pos := 0
	for {
		ptLim := len(w.plaintext)
		if w.encryptedSegmentCnt == 0 {
			ptLim -= w.firstCiphertextSegmentOffset
		}
		n := copy(w.plaintext[w.plaintextPos:ptLim], p[pos:])
		w.plaintextPos += n
		pos += n
		if pos == len(p) {
			break
		}

		nonce, err := generateSegmentNonce(w.nonceSize, w.noncePrefix, w.encryptedSegmentCnt, false)
		if err != nil {
			return pos, err
		}

		w.ciphertext, err = w.segmentEncrypter.EncryptSegment(w.plaintext[:ptLim], nonce)
		if err != nil {
			return pos, err
		}

		if _, err := w.w.Write(w.ciphertext); err != nil {
			return pos, err
		}

		w.plaintextPos = 0
		w.encryptedSegmentCnt++
	}
	return pos, nil
}

// Close encrypts the remaining data, flushes it to the underlying writer and
// closes this writer.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}

	nonce, err := generateSegmentNonce(w.nonceSize, w.noncePrefix, w.encryptedSegmentCnt, true)
	if err != nil {
		return err
	}

	w.ciphertext, err = w.segmentEncrypter.EncryptSegment(w.plaintext[:w.plaintextPos], nonce)
	if err != nil {
		return err
	}

	if _, err := w.w.Write(w.ciphertext); err != nil {
		return err
	}

	w.plaintextPos = 0
	w.encryptedSegmentCnt++
	w.closed = true
	return nil
}

// SegmentDecrypter facilitates implementing various streaming AEAD encryption modes.
type SegmentDecrypter interface {
	DecryptSegment(segment, nonce []byte) ([]byte, error)
}

// Reader facilitates the decryption of ciphertexts created using a Writer.
//
// The scheme used for decrypting segments is specified by providing a
// SegmentDecrypter implementation. The implementation must align
// with the SegmentEncrypter used in the Writer.
type Reader struct {
	r                            io.Reader
	segmentDecrypter             SegmentDecrypter
	decryptedSegmentCnt          uint64
	firstCiphertextSegmentOffset int
	nonceSize                    int
	noncePrefix                  []byte
	plaintext                    []byte
	plaintextPos                 int
	ciphertext                   []byte
	ciphertextPos                int
}

// ReaderParams contains the options for instantiating a Reader via NewReader().
type ReaderParams struct {
	// R is the underlying reader being wrapped.
	R io.Reader

	// SegmentDecrypter provides a method for decrypting segments.
	SegmentDecrypter SegmentDecrypter

	// NonceSize is the length of generated nonces. It must match the NonceSize
	// of the Writer used to create the ciphertext.
	NonceSize int

	// NoncePrefix is a constant that all nocnes throughout the ciphertext start
	// with. It's extracted from the header of the ciphertext.
	NoncePrefix []byte

	// The size of the ciphertext segments.
	CiphertextSegmentSize int

	// FirstCiphertexSegmentOffset indicates where the ciphertext actually begins
	// in R. This allows for the existence of overhead in the stream unrelated to
	// this encryption scheme.
	FirstCiphertextSegmentOffset int
}

// NewReader creates a new Reader instance.
func NewReader(params ReaderParams) (*Reader, error) {
	if params.NonceSize-len(params.NoncePrefix) < 5 {
		return nil, ErrNonceSizeTooShort
	}
	return &Reader{
		r:                            params.R,
		segmentDecrypter:             params.SegmentDecrypter,
		nonceSize:                    params.NonceSize,
		noncePrefix:                  params.NoncePrefix,
		firstCiphertextSegmentOffset: params.FirstCiphertextSegmentOffset,

		// Allocate an extra byte to detect the last segment.
		ciphertext: make([]byte, params.CiphertextSegmentSize+1),
	}, nil
}

// Read decrypts data from underlying reader and passes it to p.
func (r *Reader) Read(p []byte) (int, error) {
	if r.plaintextPos < len(r.plaintext) {
		n := copy(p, r.plaintext[r.plaintextPos:])
		r.plaintextPos += n
		return n, nil
	}

	r.plaintextPos = 0

	ctLim := len(r.ciphertext)
	if r.decryptedSegmentCnt == 0 {
		ctLim -= r.firstCiphertextSegmentOffset
	}
	n, err := io.ReadFull(r.r, r.ciphertext[r.ciphertextPos:ctLim])
	if err != nil && err != io.ErrUnexpectedEOF {
		return 0, err
	}

	var (
		lastSegment bool
		segment     int
	)
	if err != nil {
		lastSegment = true
		segment = r.ciphertextPos + n
	} else {
		segment = r.ciphertextPos + n - 1
	}

	if segment < 0 {
		return 0, ErrCiphertextSegmentTooShort
	}

	nonce, err := generateSegmentNonce(r.nonceSize, r.noncePrefix, r.decryptedSegmentCnt, lastSegment)
	if err != nil {
		return 0, err
	}

	r.plaintext, err = r.segmentDecrypter.DecryptSegment(r.ciphertext[:segment], nonce)
	if err != nil {
		return 0, err
	}

	// Copy 1 byte remainder to the beginning of ciphertext.
	if !lastSegment {
		remainderOffset := segment
		r.ciphertext[0] = r.ciphertext[remainderOffset]
		r.ciphertextPos = 1
	}

	r.decryptedSegmentCnt++

	n = copy(p, r.plaintext)
	r.plaintextPos = n
	return n, nil
}

// generateSegmentNonce returns a nonce for a segment.
//
// The format of the nonce is:
//
//   nonce_prefix || ctr || last_block.
//
// nonce_prefix is a constant prefix used throughout the whole ciphertext.
//
// The ctr is a 32 bit counter.
//
// last_block is 1 byte which is set to 1 for the last segment and 0
// otherwise.
func generateSegmentNonce(size int, prefix []byte, segmentNum uint64, last bool) ([]byte, error) {
	if segmentNum >= math.MaxUint32 {
		return nil, ErrTooManySegments
	}

	nonce := make([]byte, size)
	copy(nonce, prefix)
	offset := len(prefix)
	binary.BigEndian.PutUint32(nonce[offset:], uint32(segmentNum))
	offset += 4
	if last {
		nonce[offset] = 1
	}
	return nonce, nil
}
