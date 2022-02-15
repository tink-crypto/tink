// Copyright 2021 Google LLC
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

// Package hpke provides implementations of Hybrid Public Key Encryption.
package hpke

import (
	"encoding/binary"
	"fmt"
)

const (
	// All identifier values are specified in
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html.
	// Mode identifiers.
	baseMode uint8 = 0x00

	// KEM algorithm identifiers.
	x25519HKDFSHA256 uint16 = 0x0020

	// KDF algorithm identifiers.
	hkdfSHA256 uint16 = 0x0001

	// AEAD algorithm identifiers.
	aes128GCM        uint16 = 0x0001
	aes256GCM        uint16 = 0x0002
	chaCha20Poly1305 uint16 = 0x0003

	sha256 = "SHA256"
	hpkeV1 = "HPKE-v1"
)

var (
	emptySalt = []byte{}
	emptyIKM  = []byte{}
)

// kemSuiteID generates the KEM suite ID from kemID according to
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-4.1-5.
func kemSuiteID(kemID uint16) []byte {
	return appendBigEndianUint16([]byte("KEM"), kemID)
}

// hpkeSuiteID generates the HPKE suite ID according to
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-5.1-8.
func hpkeSuiteID(kemID, kdfID, aeadID uint16) []byte {
	var res []byte
	res = append(res, "HPKE"...)
	res = appendBigEndianUint16(res, kemID)
	res = appendBigEndianUint16(res, kdfID)
	res = appendBigEndianUint16(res, aeadID)
	return res
}

// keyScheduleContext creates the key_schedule_context defined at
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-5.1-10.
func keyScheduleContext(mode uint8, pskIDHash, infoHash []byte) []byte {
	var res []byte
	res = append(res, mode)
	res = append(res, pskIDHash...)
	res = append(res, infoHash...)
	return res
}

// labelIKM returns a labeled IKM according to LabeledExtract() defined at
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-4.
func labelIKM(label string, ikm, suiteID []byte) []byte {
	var res []byte
	res = append(res, hpkeV1...)
	res = append(res, suiteID...)
	res = append(res, label...)
	res = append(res, ikm...)
	return res
}

// labelInfo returns a labeled info according to LabeledExpand() defined at
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-4.
func labelInfo(label string, info, suiteID []byte, length int) ([]byte, error) {
	length16 := uint16(length)
	if int(length16) != length {
		return nil, fmt.Errorf("length %d must be a valid uint16 value", length)
	}

	var res []byte
	res = appendBigEndianUint16(res, length16)
	res = append(res, hpkeV1...)
	res = append(res, suiteID...)
	res = append(res, label...)
	res = append(res, info...)
	return res, nil
}

// appendBigEndianUint16 appends a uint16 v to the end of a byte array out.
func appendBigEndianUint16(out []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return append(out, b...)
}
