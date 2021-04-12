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

package subtle

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	subtleaead "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/streamingaead/subtle/noncebased"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
)

const (
	// AESGCMHKDFNonceSizeInBytes is the size of the nonces used for GCM.
	AESGCMHKDFNonceSizeInBytes = 12

	// AESGCMHKDFNoncePrefixSizeInBytes is the size of the randomly generated
	// nonce prefix.
	AESGCMHKDFNoncePrefixSizeInBytes = 7

	// AESGCMHKDFTagSizeInBytes is the size of the tags of each ciphertext
	// segment.
	AESGCMHKDFTagSizeInBytes = 16
)

// AESGCMHKDF implements streaming AEAD encryption using AES-GCM.
//
// Each ciphertext uses a new AES-GCM key. These keys are derived using HKDF
// and are derived from the key derivation key, a randomly chosen salt of the
// same size as the key and a nonce prefix.
type AESGCMHKDF struct {
	MainKey                      []byte
	hkdfAlg                      string
	keySizeInBytes               int
	ciphertextSegmentSize        int
	firstCiphertextSegmentOffset int
	plaintextSegmentSize         int
}

// NewAESGCMHKDF initializes a streaming primitive with a key derivation key
// and encryption parameters.
//
// mainKey is an input keying material used to derive sub keys.
//
// hkdfAlg is a MAC algorithm name, e.g., HmacSha256, used for the HKDF key
// derivation.
//
// keySizeInBytes argument is a key size of the sub keys.
//
// ciphertextSegmentSize argument is the size of ciphertext segments.
//
// firstSegmentOffset argument is the offset of the first ciphertext segment.
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
	headerLen := 1 + keySizeInBytes + AESGCMHKDFNoncePrefixSizeInBytes
	if ciphertextSegmentSize <= firstSegmentOffset+headerLen+AESGCMHKDFTagSizeInBytes {
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
		plaintextSegmentSize:         ciphertextSegmentSize - AESGCMHKDFTagSizeInBytes,
	}, nil
}

// HeaderLength returns the length of the encryption header.
func (a *AESGCMHKDF) HeaderLength() int {
	return 1 + a.keySizeInBytes + AESGCMHKDFNoncePrefixSizeInBytes
}

// deriveKey returns a key derived from the given main key using salt and aad
// parameters.
func (a *AESGCMHKDF) deriveKey(salt, aad []byte) ([]byte, error) {
	return subtle.ComputeHKDF(a.hkdfAlg, a.MainKey, salt, aad, uint32(a.keySizeInBytes))
}

// newCipher creates a new AES-GCM cipher using the given key and the crypto library.
func (a *AESGCMHKDF) newCipher(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCMCipher, err := cipher.NewGCMWithTagSize(aesCipher, AESGCMHKDFTagSizeInBytes)
	if err != nil {
		return nil, err
	}
	return aesGCMCipher, nil
}

type aesGCMHKDFSegmentEncrypter struct {
	noncebased.SegmentEncrypter
	cipher cipher.AEAD
}

func (e aesGCMHKDFSegmentEncrypter) EncryptSegment(segment, nonce []byte) ([]byte, error) {
	result := make([]byte, len(segment))
	result = e.cipher.Seal(result[0:0], nonce, segment, nil)
	return result, nil
}

// aesGCMHKDFWriter works as a wrapper around underlying io.Writer, which is
// responsible for encrypting written data. The data is encrypted and flushed
// in segments of a given size.  Once all the data is written aesGCMHKDFWriter
// must be closed.
type aesGCMHKDFWriter struct {
	*noncebased.Writer
}

// NewEncryptingWriter returns a wrapper around underlying io.Writer, such that
// any write-operation via the wrapper results in AEAD-encryption of the
// written data, using aad as associated authenticated data. The associated
// data is not included in the ciphertext and has to be passed in as parameter
// for decryption.
func (a *AESGCMHKDF) NewEncryptingWriter(w io.Writer, aad []byte) (io.WriteCloser, error) {
	salt := random.GetRandomBytes(uint32(a.keySizeInBytes))
	noncePrefix := random.GetRandomBytes(AESGCMHKDFNoncePrefixSizeInBytes)

	dkey, err := a.deriveKey(salt, aad)
	if err != nil {
		return nil, err
	}

	cipher, err := a.newCipher(dkey)
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

	nw, err := noncebased.NewWriter(noncebased.WriterParams{
		W:                            w,
		SegmentEncrypter:             aesGCMHKDFSegmentEncrypter{cipher: cipher},
		NonceSize:                    AESGCMHKDFNonceSizeInBytes,
		NoncePrefix:                  noncePrefix,
		PlaintextSegmentSize:         a.plaintextSegmentSize,
		FirstCiphertextSegmentOffset: a.firstCiphertextSegmentOffset,
	})
	if err != nil {
		return nil, err
	}

	return &aesGCMHKDFWriter{Writer: nw}, nil
}

type aesGCMHKDFSegmentDecrypter struct {
	noncebased.SegmentDecrypter
	cipher cipher.AEAD
}

func (d aesGCMHKDFSegmentDecrypter) DecryptSegment(segment, nonce []byte) ([]byte, error) {
	result := make([]byte, 0, len(segment))
	result, err := d.cipher.Open(result, nonce, segment, nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// aesGCMHKDFReader works as a wrapper around underlying io.Reader.
type aesGCMHKDFReader struct {
	*noncebased.Reader
}

// NewDecryptingReader returns a wrapper around underlying io.Reader, such that
// any read-operation via the wrapper results in AEAD-decryption of the
// underlying ciphertext, using aad as associated authenticated data.
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

	noncePrefix := make([]byte, AESGCMHKDFNoncePrefixSizeInBytes)
	if _, err := io.ReadFull(r, noncePrefix); err != nil {
		return nil, fmt.Errorf("cannot read noncePrefix: %v", err)
	}

	dkey, err := a.deriveKey(salt, aad)
	if err != nil {
		return nil, err
	}

	cipher, err := a.newCipher(dkey)
	if err != nil {
		return nil, err
	}

	nr, err := noncebased.NewReader(noncebased.ReaderParams{
		R:                            r,
		SegmentDecrypter:             aesGCMHKDFSegmentDecrypter{cipher: cipher},
		NonceSize:                    AESGCMHKDFNonceSizeInBytes,
		NoncePrefix:                  noncePrefix,
		CiphertextSegmentSize:        a.ciphertextSegmentSize,
		FirstCiphertextSegmentOffset: a.firstCiphertextSegmentOffset,
	})
	if err != nil {
		return nil, err
	}

	return &aesGCMHKDFReader{Reader: nr}, nil
}
