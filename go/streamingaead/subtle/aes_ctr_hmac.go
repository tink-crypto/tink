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

	// Placeholder for internal crypto/cipher allowlist, please ignore.
	subtleaead "github.com/google/tink/go/aead/subtle"
	subtlemac "github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/streamingaead/subtle/noncebased"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
)

const (
	// AESCTRHMACNonceSizeInBytes is the size of the nonces used as IVs for CTR.
	AESCTRHMACNonceSizeInBytes = 16

	// AESCTRHMACNoncePrefixSizeInBytes is the size of the nonce prefix.
	AESCTRHMACNoncePrefixSizeInBytes = 7

	// AESCTRHMACKeySizeInBytes is the size of the HMAC key.
	AESCTRHMACKeySizeInBytes = 32
)

// AESCTRHMAC implements streaming AEAD encryption using AES-CTR and HMAC.
//
// Each ciphertext uses new AES-CTR and HMAC keys. These keys are derived using
// HKDF and are derived from the key derivation key, a randomly chosen salt of
// the same size as the key and a nonce prefix.
type AESCTRHMAC struct {
	MainKey                      []byte
	hkdfAlg                      string
	keySizeInBytes               int
	tagAlg                       string
	tagSizeInBytes               int
	ciphertextSegmentSize        int
	plaintextSegmentSize         int
	firstCiphertextSegmentOffset int
}

// NewAESCTRHMAC initializes an AESCTRHMAC primitive with a key derivation key
// and encryption parameters.
//
// mainKey is input keying material used to derive sub keys.
//
// hkdfAlg is a MAC algorithm name, e.g., HmacSha256, used for the HKDF key
// derivation.
//
// keySizeInBytes is the key size of the sub keys.
//
// tagAlg is the MAC algorithm name, e.g. HmacSha256, used for generating per
// segment tags.
//
// tagSizeInBytes is the size of the per segment tags.
//
// ciphertextSegmentSize is the size of ciphertext segments.
//
// firstSegmentOffset is the offset of the first ciphertext segment.
func NewAESCTRHMAC(
	mainKey []byte,
	hkdfAlg string,
	keySizeInBytes int,
	tagAlg string,
	tagSizeInBytes int,
	ciphertextSegmentSize int,
	firstSegmentOffset int,
) (*AESCTRHMAC, error) {
	if len(mainKey) < 16 || len(mainKey) < keySizeInBytes {
		return nil, errors.New("mainKey too short")
	}
	if err := subtleaead.ValidateAESKeySize(uint32(keySizeInBytes)); err != nil {
		return nil, err
	}
	if tagSizeInBytes < 10 {
		return nil, errors.New("tag size too small")
	}
	digestSize, err := subtle.GetHashDigestSize(tagAlg)
	if err != nil {
		return nil, err
	}
	if uint32(tagSizeInBytes) > digestSize {
		return nil, errors.New("tag size too big")
	}
	headerLen := 1 + keySizeInBytes + AESCTRHMACNoncePrefixSizeInBytes
	if ciphertextSegmentSize <= firstSegmentOffset+headerLen+tagSizeInBytes {
		return nil, errors.New("ciphertextSegmentSize too small")
	}

	keyClone := make([]byte, len(mainKey))
	copy(keyClone, mainKey)

	return &AESCTRHMAC{
		MainKey:                      keyClone,
		hkdfAlg:                      hkdfAlg,
		keySizeInBytes:               keySizeInBytes,
		tagAlg:                       tagAlg,
		tagSizeInBytes:               tagSizeInBytes,
		ciphertextSegmentSize:        ciphertextSegmentSize,
		firstCiphertextSegmentOffset: firstSegmentOffset + headerLen,
		plaintextSegmentSize:         ciphertextSegmentSize - tagSizeInBytes,
	}, nil
}

// HeaderLength returns the length of the encryption header.
func (a *AESCTRHMAC) HeaderLength() int {
	return 1 + a.keySizeInBytes + AESCTRHMACNoncePrefixSizeInBytes
}

// deriveKeyMaterial returns a key derived from the main key using salt and aad
// as parameters.
func (a *AESCTRHMAC) deriveKeyMaterial(salt, aad []byte) ([]byte, error) {
	keyMaterialSize := a.keySizeInBytes + AESCTRHMACKeySizeInBytes
	return subtle.ComputeHKDF(a.hkdfAlg, a.MainKey, salt, aad, uint32(keyMaterialSize))
}

type aesCTRHMACSegmentEncrypter struct {
	noncebased.SegmentEncrypter
	blockCipher    cipher.Block
	hmac           *subtlemac.HMAC
	tagSizeInBytes int
}

func (e aesCTRHMACSegmentEncrypter) EncryptSegment(segment, nonce []byte) ([]byte, error) {
	sLen := len(segment)
	nLen := len(nonce)
	ctLen := sLen + e.tagSizeInBytes
	ciphertext := make([]byte, ctLen)

	stream := cipher.NewCTR(e.blockCipher, nonce)
	stream.XORKeyStream(ciphertext, segment)

	macInput := make([]byte, nLen+sLen)
	copy(macInput, nonce)
	copy(macInput[nLen:], ciphertext)
	tag, err := e.hmac.ComputeMAC(macInput)
	if err != nil {
		return nil, err
	}
	copy(ciphertext[sLen:], tag)

	return ciphertext, nil
}

// aesCTRHMACWriter works as a wrapper around underlying io.Writer, which is
// responsible for encrypting written data. The data is encrypted and flushed
// in segments of a given size.  Once all the data is written aesCTRHMACWriter
// must be closed.
type aesCTRHMACWriter struct {
	*noncebased.Writer
}

// NewEncryptingWriter returns a wrapper around underlying io.Writer, such that
// any write-operation via the wrapper results in AEAD-encryption of the
// written data, using aad as associated authenticated data. The associated
// data is not included in the ciphertext and has to be passed in as parameter
// for decryption.
func (a *AESCTRHMAC) NewEncryptingWriter(w io.Writer, aad []byte) (io.WriteCloser, error) {
	salt := random.GetRandomBytes(uint32(a.keySizeInBytes))
	noncePrefix := random.GetRandomBytes(AESCTRHMACNoncePrefixSizeInBytes)

	km, err := a.deriveKeyMaterial(salt, aad)
	if err != nil {
		return nil, err
	}

	aesKey := make([]byte, a.keySizeInBytes)
	copy(aesKey, km)
	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	hmacKey := make([]byte, AESCTRHMACKeySizeInBytes)
	copy(hmacKey, km[a.keySizeInBytes:])
	hmac, err := subtlemac.NewHMAC(a.tagAlg, hmacKey, uint32(a.tagSizeInBytes))
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
		W: w,
		SegmentEncrypter: aesCTRHMACSegmentEncrypter{
			blockCipher:    blockCipher,
			hmac:           hmac,
			tagSizeInBytes: a.tagSizeInBytes,
		},
		NonceSize:                    AESCTRHMACNonceSizeInBytes,
		NoncePrefix:                  noncePrefix,
		PlaintextSegmentSize:         a.plaintextSegmentSize,
		FirstCiphertextSegmentOffset: a.firstCiphertextSegmentOffset,
	})
	if err != nil {
		return nil, err
	}
	return &aesCTRHMACWriter{Writer: nw}, nil
}

type aesCTRHMACSegmentDecrypter struct {
	noncebased.SegmentDecrypter
	blockCipher    cipher.Block
	hmac           *subtlemac.HMAC
	tagSizeInBytes int
}

func (d aesCTRHMACSegmentDecrypter) DecryptSegment(segment, nonce []byte) ([]byte, error) {
	sLen := len(segment)
	nLen := len(nonce)
	tagStart := sLen - d.tagSizeInBytes
	if tagStart < 0 {
		return nil, errors.New("segment too short")
	}
	tag := segment[tagStart:]

	macInput := make([]byte, nLen+tagStart)
	copy(macInput, nonce)
	copy(macInput[nLen:], segment[:tagStart])
	if err := d.hmac.VerifyMAC(tag, macInput); err != nil {
		return nil, errors.New("tag mismatch")
	}

	result := make([]byte, tagStart)
	stream := cipher.NewCTR(d.blockCipher, nonce)
	stream.XORKeyStream(result, segment[:tagStart])
	return result, nil
}

// aesCTRHMACReader works as a wrapper around underlying io.Reader.
type aesCTRHMACReader struct {
	*noncebased.Reader
}

// NewDecryptingReader returns a wrapper around underlying io.Reader, such that
// any read-operation via the wrapper results in AEAD-decryption of the
// underlying ciphertext, using aad as associated authenticated data.
func (a *AESCTRHMAC) NewDecryptingReader(r io.Reader, aad []byte) (io.Reader, error) {
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

	noncePrefix := make([]byte, AESCTRHMACNoncePrefixSizeInBytes)
	if _, err := io.ReadFull(r, noncePrefix); err != nil {
		return nil, fmt.Errorf("cannot read noncePrefix: %v", err)
	}

	km, err := a.deriveKeyMaterial(salt, aad)
	if err != nil {
		return nil, err
	}

	aesKey := make([]byte, a.keySizeInBytes)
	copy(aesKey, km)
	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	hmacKey := make([]byte, AESCTRHMACKeySizeInBytes)
	copy(hmacKey, km[a.keySizeInBytes:])
	hmac, err := subtlemac.NewHMAC(a.tagAlg, hmacKey, uint32(a.tagSizeInBytes))
	if err != nil {
		return nil, err
	}

	nr, err := noncebased.NewReader(noncebased.ReaderParams{
		R: r,
		SegmentDecrypter: aesCTRHMACSegmentDecrypter{
			blockCipher:    blockCipher,
			hmac:           hmac,
			tagSizeInBytes: a.tagSizeInBytes,
		},
		NonceSize:                    AESCTRHMACNonceSizeInBytes,
		NoncePrefix:                  noncePrefix,
		CiphertextSegmentSize:        a.ciphertextSegmentSize,
		FirstCiphertextSegmentOffset: a.firstCiphertextSegmentOffset,
	})
	if err != nil {
		return nil, err
	}

	return &aesCTRHMACReader{Reader: nr}, nil
}
