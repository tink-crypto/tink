// Copyright 2022 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

package aead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// TODO(b/201070904): Rename to AESGCMInsecureNonce and simplify by getting rid
// of the prependIV bool.

const (
	// aesGCMMaxPlaintextSize is the maximum plaintext size defined by RFC 5116.
	aesGCMMaxPlaintextSize = (1 << 36) - 31

	intSize             = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt              = 1<<(intSize-1) - 1
	maxIntPlaintextSize = maxInt - AESGCMIVSize - AESGCMTagSize

	minNoIVCiphertextSize      = AESGCMTagSize
	minPrependIVCiphertextSize = AESGCMIVSize + AESGCMTagSize
)

// AESGCMInsecureIV is an insecure implementation of the AEAD interface that
// permits the user to set the IV.
type AESGCMInsecureIV struct {
	Key       []byte
	prependIV bool
}

// NewAESGCMInsecureIV returns an AESGCMInsecureIV instance, where key is the
// AES key with length 16 bytes (AES-128) or 32 bytes (AES-256).
//
// If prependIV is true, both the ciphertext returned from Encrypt and passed
// into Decrypt are prefixed with the IV.
func NewAESGCMInsecureIV(key []byte, prependIV bool) (*AESGCMInsecureIV, error) {
	keySize := uint32(len(key))
	if err := ValidateAESKeySize(keySize); err != nil {
		return nil, fmt.Errorf("invalid AES key size: %s", err)
	}
	return &AESGCMInsecureIV{
		Key:       key,
		prependIV: prependIV,
	}, nil
}

// Encrypt encrypts plaintext with iv as the initialization vector and
// associatedData as associated data.
//
// If prependIV is true, the returned ciphertext contains both the IV used for
// encryption and the actual ciphertext.
// If false, the returned ciphertext contains only the actual ciphertext.
//
// Note: The crypto library's AES-GCM implementation always returns the
// ciphertext with an AESGCMTagSize (16-byte) tag.
func (i *AESGCMInsecureIV) Encrypt(iv, plaintext, associatedData []byte) ([]byte, error) {
	if got, want := len(iv), AESGCMIVSize; got != want {
		return nil, fmt.Errorf("unexpected IV size: got %d, want %d", got, want)
	}
	// Seal() checks plaintext length, but this duplicated check avoids panic.
	var maxPlaintextSize uint64 = maxIntPlaintextSize
	if maxIntPlaintextSize > aesGCMMaxPlaintextSize {
		maxPlaintextSize = aesGCMMaxPlaintextSize
	}
	if uint64(len(plaintext)) > maxPlaintextSize {
		return nil, fmt.Errorf("plaintext too long: got %d", len(plaintext))
	}

	cipher, err := i.newCipher()
	if err != nil {
		return nil, err
	}
	ciphertext := cipher.Seal(nil, iv, plaintext, associatedData)

	if i.prependIV {
		return append(iv, ciphertext...), nil
	}
	return ciphertext, nil
}

// Decrypt decrypts ciphertext with iv as the initialization vector and
// associatedData as associated data.
//
// If prependIV is true, the iv argument and the first AESGCMIVSize bytes of
// ciphertext must be equal. The ciphertext argument is as follows:
//     | iv | actual ciphertext | tag |
//
// If false, the ciphertext argument is as follows:
//     | actual ciphertext | tag |
func (i *AESGCMInsecureIV) Decrypt(iv, ciphertext, associatedData []byte) ([]byte, error) {
	if len(iv) != AESGCMIVSize {
		return nil, fmt.Errorf("unexpected IV size: got %d, want %d", len(iv), AESGCMIVSize)
	}

	var actualCiphertext []byte
	if i.prependIV {
		if len(ciphertext) < minPrependIVCiphertextSize {
			return nil, fmt.Errorf("ciphertext too short: got %d, want >= %d", len(ciphertext), minPrependIVCiphertextSize)
		}
		if !bytes.Equal(iv, ciphertext[:AESGCMIVSize]) {
			return nil, fmt.Errorf("unequal IVs: iv argument %x, ct prefix %x", iv, ciphertext[:AESGCMIVSize])
		}
		actualCiphertext = ciphertext[AESGCMIVSize:]
	} else {
		if len(ciphertext) < minNoIVCiphertextSize {
			return nil, fmt.Errorf("ciphertext too short: got %d, want >= %d", len(ciphertext), minNoIVCiphertextSize)
		}
		actualCiphertext = ciphertext
	}

	cipher, err := i.newCipher()
	if err != nil {
		return nil, err
	}
	plaintext, err := cipher.Open(nil, iv, actualCiphertext, associatedData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// newCipher creates a new AES-GCM cipher using the given key and the crypto
// library.
func (i *AESGCMInsecureIV) newCipher() (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(i.Key)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}
	ret, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}
	return ret, nil
}
