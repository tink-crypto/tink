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

// Package subtle provides subtle implementations of the DeterministicAEAD
// primitive.
package subtle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"

	// Placeholder for internal crypto/cipher allowlist, please ignore.
	// Placeholder for internal crypto/subtle allowlist, please ignore.
)

// AESSIV is an implementation of AES-SIV-CMAC as defined in
// https://tools.ietf.org/html/rfc5297.
//
// AESSIV implements a deterministic encryption with associated data (i.e. the
// DeterministicAEAD interface). Hence the implementation below is restricted
// to one AD component.
//
// Security Note:
//
// Chatterjee, Menezes and Sarkar analyze AES-SIV in Section 5.1 of
// https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf
//
// Their analysis shows that AES-SIV is susceptible to an attack in
// a multi-user setting. Concretely, if an attacker knows the encryption
// of a message m encrypted and authenticated with k different keys,
// then it is possible  to find one of the MAC keys in time 2^b / k
// where b is the size of the MAC key. A consequence of this attack
// is that 128-bit MAC keys give unsufficient security.
// Since 192-bit AES keys are not supported by tink for voodoo reasons
// and RFC 5297 only supports same size encryption and MAC keys this
// implies that keys must be 64 bytes (2*256 bits) long.
type AESSIV struct {
	K1     []byte
	K2     []byte
	CmacK1 []byte
	CmacK2 []byte
	Cipher cipher.Block
}

const (
	// AESSIVKeySize is the key size in bytes.
	AESSIVKeySize = 64

	intSize = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt  = 1<<(intSize-1) - 1
)

// NewAESSIV returns an AESSIV instance.
func NewAESSIV(key []byte) (*AESSIV, error) {
	if len(key) != AESSIVKeySize {
		return nil, fmt.Errorf("aes_siv: invalid key size %d", len(key))
	}

	k1 := key[:32]
	k2 := key[32:]
	c, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("aes_siv: aes.NewCipher(%s) failed, %v", k1, err)
	}

	block := make([]byte, aes.BlockSize)
	c.Encrypt(block, block)
	multiplyByX(block)
	cmacK1 := make([]byte, aes.BlockSize)
	copy(cmacK1, block)
	multiplyByX(block)
	cmacK2 := make([]byte, aes.BlockSize)
	copy(cmacK2, block)

	return &AESSIV{
		K1:     k1,
		K2:     k2,
		CmacK1: cmacK1,
		CmacK2: cmacK2,
		Cipher: c,
	}, nil
}

// multiplyByX multiplies an element in GF(2^128) by its generator.
//
// This function is incorrectly named "doubling" in section 2.3 of RFC 5297.
func multiplyByX(block []byte) {
	carry := int(block[0] >> 7)
	for i := 0; i < aes.BlockSize-1; i++ {
		block[i] = (block[i] << 1) | (block[i+1] >> 7)
	}

	block[aes.BlockSize-1] = (block[aes.BlockSize-1] << 1) ^ byte(subtle.ConstantTimeSelect(carry, 0x87, 0x00))
}

// EncryptDeterministically deterministically encrypts plaintext with associatedData.
func (asc *AESSIV) EncryptDeterministically(plaintext, associatedData []byte) ([]byte, error) {
	if len(plaintext) > maxInt-aes.BlockSize {
		return nil, fmt.Errorf("aes_siv: plaintext too long")
	}
	siv := make([]byte, aes.BlockSize)
	asc.s2v(plaintext, associatedData, siv)

	ct := make([]byte, len(plaintext)+aes.BlockSize)
	copy(ct[:aes.BlockSize], siv)
	if err := asc.ctrCrypt(siv, plaintext, ct[aes.BlockSize:]); err != nil {
		return nil, err
	}

	return ct, nil
}

// DecryptDeterministically deterministically decrypts ciphertext with associatedData.
func (asc *AESSIV) DecryptDeterministically(ciphertext, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("aes_siv: ciphertext is too short")
	}

	pt := make([]byte, len(ciphertext)-aes.BlockSize)
	siv := ciphertext[:aes.BlockSize]
	asc.ctrCrypt(siv, ciphertext[aes.BlockSize:], pt)
	s2v := make([]byte, aes.BlockSize)
	asc.s2v(pt, associatedData, s2v)

	diff := byte(0)
	for i := 0; i < aes.BlockSize; i++ {
		diff |= siv[i] ^ s2v[i]
	}
	if diff != 0 {
		return nil, errors.New("aes_siv: invalid ciphertext")
	}

	return pt, nil
}

// ctrCrypt encrypts (or decrypts) the bytes in in using an SIV and writes the
// result to out.
func (asc *AESSIV) ctrCrypt(siv, in, out []byte) error {
	// siv might be used outside of ctrCrypt(), so making a copy of it.
	iv := make([]byte, aes.BlockSize)
	copy(iv, siv)
	iv[8] &= 0x7f
	iv[12] &= 0x7f

	c, err := aes.NewCipher(asc.K2)
	if err != nil {
		return fmt.Errorf("aes_siv: aes.NewCipher(%s) failed, %v", asc.K2, err)
	}

	steam := cipher.NewCTR(c, iv)
	steam.XORKeyStream(out, in)
	return nil
}

// s2v is a Pseudo-Random Function (PRF) construction:
// https://tools.ietf.org/html/rfc5297.
func (asc *AESSIV) s2v(msg, ad, siv []byte) {
	block := make([]byte, aes.BlockSize)
	asc.cmac(block, block)
	multiplyByX(block)

	adMac := make([]byte, aes.BlockSize)
	asc.cmac(ad, adMac)
	xorBlock(adMac, block)

	if len(msg) >= aes.BlockSize {
		asc.cmacLong(msg, block, siv)
	} else {
		multiplyByX(block)
		for i := 0; i < len(msg); i++ {
			block[i] ^= msg[i]
		}
		block[len(msg)] ^= 0x80
		asc.cmac(block, siv)
	}
}

// cmacLong computes CMAC(XorEnd(data, last)), where XorEnd xors the bytes in
// last to the last bytes in data.
//
// The size of the data must be at least 16 bytes.
func (asc *AESSIV) cmacLong(data, last, mac []byte) {
	block := make([]byte, aes.BlockSize)
	copy(block, data[:aes.BlockSize])

	idx := aes.BlockSize
	for aes.BlockSize <= len(data)-idx {
		asc.Cipher.Encrypt(block, block)
		xorBlock(data[idx:idx+aes.BlockSize], block)
		idx += aes.BlockSize
	}

	remaining := len(data) - idx
	for i := 0; i < aes.BlockSize-remaining; i++ {
		block[remaining+i] ^= last[i]
	}
	if remaining == 0 {
		xorBlock(asc.CmacK1, block)
	} else {
		asc.Cipher.Encrypt(block, block)
		for i := 0; i < remaining; i++ {
			block[i] ^= last[aes.BlockSize-remaining+i]
			block[i] ^= data[idx+i]
		}
		block[remaining] ^= 0x80
		xorBlock(asc.CmacK2, block)
	}

	asc.Cipher.Encrypt(mac, block)
}

// cmac computes a CMAC of some data.
func (asc *AESSIV) cmac(data, mac []byte) {
	numBs := int(math.Ceil(float64(len(data)) / aes.BlockSize))
	if numBs == 0 {
		numBs = 1
	}
	lastBSize := len(data) - (numBs-1)*aes.BlockSize

	block := make([]byte, aes.BlockSize)
	idx := 0
	for i := 0; i < numBs-1; i++ {
		xorBlock(data[idx:idx+aes.BlockSize], block)
		asc.Cipher.Encrypt(block, block)
		idx += aes.BlockSize
	}
	for j := 0; j < lastBSize; j++ {
		block[j] ^= data[idx+j]
	}

	if lastBSize == aes.BlockSize {
		xorBlock(asc.CmacK1, block)
	} else {
		block[lastBSize] ^= 0x80
		xorBlock(asc.CmacK2, block)
	}

	asc.Cipher.Encrypt(mac, block)
}

// xorBlock sets block[i] = x[i] ^ block[i].
func xorBlock(x, block []byte) {
	for i := 0; i < aes.BlockSize; i++ {
		block[i] ^= x[i]
	}
}
