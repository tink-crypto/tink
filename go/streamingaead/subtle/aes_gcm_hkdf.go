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

// Package subtle provides subtle implementations of the Streaming AEAD primitive.
package subtle

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	subtleaead "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
)

const (
	// nonceSizeInBytes is the size of the IVs for GCM.
	nonceSizeInBytes = 12

	// NoncePrefixInBytes is the nonce has the format nonce_prefix || ctr || last_block.
	// The nonce_prefix is constant for the whole file.
	// The ctr is a 32 bit ctr, the last_block is 1 if this is the
	// last block of the file and 0 otherwise.
	NoncePrefixInBytes = 7

	// TagSizeInBytes is the size of the tags of each ciphertext segment.
	TagSizeInBytes = 16
)

// AESGCMHKDF implements streaming encryption using AES-GCM with HKDF as key derivation function.
//
// Each ciphertext uses a new AES-GCM key that is derived from the key derivation key, a randomly
// chosen salt of the same size as the key and a nonce prefix.
//
// The format of a ciphertext is header || segment_0 || segment_1 || ... || segment_k. The
// header has size HeaderLength(). Its format is headerLength || salt || prefix. where
// headerLength is 1 byte determining the size of the header, salt is a salt used in the key
// derivation and prefix is the prefix of the nonce. In principle headerLength is redundant
// information, since the length of the header can be determined from the key size.
//
// segment_i is the i-th segment of the ciphertext. The size of segment_1 .. segment_{k-1} is
// ciphertextSegmentSize. segment_0 is shorter, so that segment_0, the header and other information
// of size firstSegmentOffset align with ciphertextSegmentSize.
type AESGCMHKDF struct {
	MainKey                      []byte
	hkdfAlg                      string
	keySizeInBytes               int
	ciphertextSegmentSize        int
	firstCiphertextSegmentOffset int
	plaintextSegmentSize         int
}

// NewAESGCMHKDF initializes a streaming primitive with a key derivation key and encryption parameters.
//
// mainKey argument is an input keying material used to derive sub keys.
// hkdfAlg argument is a JCE MAC algorithm name, e.g., HmacSha256, used for the HKDF key derivation.
// keySizeInBytes argument is a key size of the sub keys
// ciphertextSegmentSize argument is the size of ciphertext segments.
// firstSegmentOffset argument is the offset of the first ciphertext segment. That means the first
// segment has size ciphertextSegmentSize - HeaderLength() - firstSegmentOffset
func NewAESGCMHKDF(
	mainKey []byte,
	hkdfAlg string,
	keySizeInBytes int,
	ciphertextSegmentSize int,
	firstSegmentOffset int,
) (*AESGCMHKDF, error) {
	if len(mainKey) < 16 || len(mainKey) < keySizeInBytes {
		return nil, errors.New("mainKey too short")
	}
	if err := subtleaead.ValidateAESKeySize(uint32(keySizeInBytes)); err != nil {
		return nil, err
	}
	headerLen := 1 + keySizeInBytes + NoncePrefixInBytes
	if ciphertextSegmentSize <= firstSegmentOffset+headerLen+TagSizeInBytes {
		return nil, errors.New("ciphertextSegmentSize too small")
	}

	keyClone := make([]byte, len(mainKey))
	copy(keyClone, mainKey)

	return &AESGCMHKDF{
		MainKey:                      keyClone,
		hkdfAlg:                      hkdfAlg,
		keySizeInBytes:               keySizeInBytes,
		ciphertextSegmentSize:        ciphertextSegmentSize,
		firstCiphertextSegmentOffset: firstSegmentOffset + headerLen,
		plaintextSegmentSize:         ciphertextSegmentSize - TagSizeInBytes,
	}, nil
}

// HeaderLength returns a length of the encryption header.
func (a *AESGCMHKDF) HeaderLength() int {
	return 1 + a.keySizeInBytes + NoncePrefixInBytes
}

// deriveKey returns a key derived from the given main key using salt and aad parameters.
func (a *AESGCMHKDF) deriveKey(salt, aad []byte) ([]byte, error) {
	return subtle.ComputeHKDF(a.hkdfAlg, a.MainKey, salt, aad, uint32(a.keySizeInBytes))
}

// aesGCMHKDFWriter works as a wrapper around underlying io.Writer, which is responsible for
// encrypting written data. The data is encrypted and flushed in segments of a given size.
// Once all the data is written aesGCMHKDFWriter must be closed.
type aesGCMHKDFWriter struct {
	encryptedSegments int
	noncePrefix       []byte
	cipher            cipher.AEAD
	wr                io.Writer

	pt                           []byte
	ptPos                        int
	ct                           []byte
	firstCiphertextSegmentOffset int

	closed bool
}

// NewEncryptingWriter returns a wrapper around underlying io.Writer, such that any write-operation
// via the wrapper results in AEAD-encryption of the written data, using aad
// as associated authenticated data. The associated data is not included in the ciphertext
// and has to be passed in as parameter for decryption.
func (a *AESGCMHKDF) NewEncryptingWriter(w io.Writer, aad []byte) (io.WriteCloser, error) {
	salt := random.GetRandomBytes(uint32(a.keySizeInBytes))
	noncePrefix := random.GetRandomBytes(NoncePrefixInBytes)

	dkey, err := a.deriveKey(salt, aad)
	if err != nil {
		return nil, err
	}

	cipher, err := newCipher(dkey)
	if err != nil {
		return nil, err
	}

	header := make([]byte, a.HeaderLength())
	header[0] = byte(a.HeaderLength())
	copy(header[1:], salt)
	copy(header[1+len(salt):], noncePrefix)
	if _, err := w.Write(header); err != nil {
		return nil, err
	}

	return &aesGCMHKDFWriter{
		noncePrefix: noncePrefix,
		cipher:      cipher,
		wr:          w,

		pt:                           make([]byte, a.plaintextSegmentSize),
		firstCiphertextSegmentOffset: a.firstCiphertextSegmentOffset,
	}, nil
}

// Write encrypts passed data and passes the encrypted data to the underlying writer.
func (w *aesGCMHKDFWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("write on closed writer")
	}

	pos := 0
	for {
		ptLim := len(w.pt)
		if w.encryptedSegments == 0 {
			ptLim = len(w.pt) - w.firstCiphertextSegmentOffset
		}
		n := copy(w.pt[w.ptPos:ptLim], p[pos:])
		w.ptPos += n
		pos += n
		if pos == len(p) {
			break
		}

		nonce := generateSegmentNonce(w.noncePrefix, w.encryptedSegments, false)

		w.ct = w.cipher.Seal(w.ct[0:0], nonce, w.pt[:ptLim], nil)
		if _, err := w.wr.Write(w.ct); err != nil {
			return pos, err
		}
		w.ptPos = 0
		w.encryptedSegments++
	}
	return pos, nil
}

// Close encrypts the remaining data, flushes it to the underlying writer and closes this writer.
func (w *aesGCMHKDFWriter) Close() error {
	if w.closed {
		return nil
	}

	nonce := generateSegmentNonce(w.noncePrefix, w.encryptedSegments, true)

	w.ct = w.cipher.Seal(w.ct[0:0], nonce, w.pt[0:w.ptPos], nil)
	if _, err := w.wr.Write(w.ct); err != nil {
		return err
	}
	w.ptPos = 0
	w.encryptedSegments++
	w.closed = true
	return nil
}

// aesGCMHKDFReader works as a wrapper around underlying io.Reader.
type aesGCMHKDFReader struct {
	decryptedSegments int
	noncePrefix       []byte
	cipher            cipher.AEAD
	underlyingReader  io.Reader

	pt                 []byte
	ptPos              int
	ct                 []byte
	ctPos              int
	firstSegmentOffset int
}

// NewDecryptingReader returns a wrapper around underlying io.Reader, such that any read-operation
// via the wrapper results in AEAD-decryption of the underlying ciphertext,
// using aad as associated authenticated data.
func (a *AESGCMHKDF) NewDecryptingReader(r io.Reader, aad []byte) (io.Reader, error) {
	hlen := make([]byte, 1)
	if _, err := io.ReadFull(r, hlen); err != nil {
		return nil, err
	}
	if hlen[0] != byte(a.HeaderLength()) {
		return nil, errors.New("invalid header length")
	}

	salt := make([]byte, a.keySizeInBytes)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, fmt.Errorf("cannot read salt: %v", err)
	}

	noncePrefix := make([]byte, NoncePrefixInBytes)
	if _, err := io.ReadFull(r, noncePrefix); err != nil {
		return nil, fmt.Errorf("cannot read noncePrefix: %v", err)
	}

	dkey, err := a.deriveKey(salt, aad)
	if err != nil {
		return nil, err
	}

	cipher, err := newCipher(dkey)
	if err != nil {
		return nil, err
	}

	return &aesGCMHKDFReader{
		noncePrefix:      noncePrefix,
		cipher:           cipher,
		underlyingReader: r,

		// Allocate an extra byte to detect last segment.
		ct:                 make([]byte, a.ciphertextSegmentSize+1),
		firstSegmentOffset: a.firstCiphertextSegmentOffset,
	}, nil
}

// Read decrypts data from underlying reader and passes it to p.
func (r *aesGCMHKDFReader) Read(p []byte) (int, error) {
	if r.ptPos < len(r.pt) {
		n := copy(p, r.pt[r.ptPos:])
		r.ptPos += n
		return n, nil
	}

	ctLim := len(r.ct)
	if r.decryptedSegments == 0 {
		ctLim -= r.firstSegmentOffset
	}

	n, err := io.ReadFull(r.underlyingReader, r.ct[r.ctPos:ctLim])
	if err != nil && err != io.ErrUnexpectedEOF {
		return 0, err
	}
	var (
		lastSegment bool
		segment     int
	)
	if err != nil {
		lastSegment = true
		segment = r.ctPos + n
	} else {
		segment = r.ctPos + n - 1
	}
	nonce := generateSegmentNonce(r.noncePrefix, r.decryptedSegments, lastSegment)
	r.pt, err = r.cipher.Open(r.pt[0:0], nonce, r.ct[:segment], nil)
	if err != nil {
		return 0, err
	}

	// Copy 1 byte remainder to the beginning of ct.
	if !lastSegment {
		r.ct[0] = r.ct[segment]
		r.ctPos = 1
	}

	r.decryptedSegments++
	r.ptPos = 0

	n = copy(p, r.pt)
	r.ptPos = n
	return n, nil
}

// newCipher creates a new AES-GCM cipher using the given key and the crypto library.
func newCipher(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ret, err := cipher.NewGCMWithTagSize(aesCipher, TagSizeInBytes)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func generateSegmentNonce(noncePrefix []byte, segmentNr int, last bool) []byte {
	var l byte
	if last {
		l = 1
	}

	nonce := make([]byte, nonceSizeInBytes)
	offs := 0
	copy(nonce, noncePrefix)
	offs += len(noncePrefix)
	binary.BigEndian.PutUint32(nonce[offs:], uint32(segmentNr))
	offs += 4
	nonce[offs] = l
	return nonce
}
