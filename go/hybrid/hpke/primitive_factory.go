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

package hpke

import (
	"fmt"

	pb "github.com/google/tink/go/proto/hpke_go_proto"
)

// newPrimitivesFromProto constructs new KEM, KDF, AEADs from HpkeParams.
func newPrimitivesFromProto(params *pb.HpkeParams) (kem, kdf, aead, error) {
	kemID, err := kemIDFromProto(params.GetKem())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kemIDFromProto(%d): %v", params.GetKem(), err)
	}
	kem, err := newKEM(kemID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("newKEM(%d): %v", kemID, err)
	}

	kdfID, err := kdfIDFromProto(params.GetKdf())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kdfIDFromProto(%d): %v", params.GetKdf(), err)
	}
	kdf, err := newKDF(kdfID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("newKDF(%d): %v", kdfID, err)
	}

	aeadID, err := aeadIDFromProto(params.GetAead())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aeadIDFromProto(%d): %v", params.GetAead(), err)
	}
	aead, err := newAEAD(aeadID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("newAEAD(%d): %v", aeadID, err)
	}

	return kem, kdf, aead, nil
}

// newKEM constructs a HPKE KEM using kemID, which are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
func newKEM(kemID uint16) (kem, error) {
	if kemID == x25519HKDFSHA256 {
		return newX25519KEM(sha256)
	}
	return nil, fmt.Errorf("KEM ID %d is not supported", kemID)
}

// kemIDFromProto returns the KEM ID from the HpkeKem enum value. KEM IDs are
// specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
func kemIDFromProto(enum pb.HpkeKem) (uint16, error) {
	if enum == pb.HpkeKem_DHKEM_X25519_HKDF_SHA256 {
		return x25519HKDFSHA256, nil
	}
	return 0, fmt.Errorf("HpkeKem enum value %d is not supported", enum)
}

// newKDF constructs a HPKE KDF using kdfID, which are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.
func newKDF(kdfID uint16) (kdf, error) {
	if kdfID == hkdfSHA256 {
		return newHKDFKDF(sha256)
	}
	return nil, fmt.Errorf("KDF ID %d is not supported", kdfID)
}

// kdfIDFromProto returns the KDF ID from the HpkeKdf enum value. KDF IDs are
// specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.
func kdfIDFromProto(enum pb.HpkeKdf) (uint16, error) {
	if enum == pb.HpkeKdf_HKDF_SHA256 {
		return hkdfSHA256, nil
	}
	return 0, fmt.Errorf("HpkeKdf enum value %d is not supported", enum)
}

// newAEAD constructs a HPKE AEAD using aeadID, which are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3.
func newAEAD(aeadID uint16) (aead, error) {
	switch aeadID {
	case aes128GCM:
		return newAESGCMAEAD(16)
	case aes256GCM:
		return newAESGCMAEAD(32)
	case chaCha20Poly1305:
		return &chaCha20Poly1305AEAD{}, nil
	default:
		return nil, fmt.Errorf("AEAD ID %d is not supported", aeadID)
	}
}

// aeadIDFromProto returns the AEAD ID from the HpkeAead enum value. AEAD IDs
// are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3.
func aeadIDFromProto(enum pb.HpkeAead) (uint16, error) {
	switch enum {
	case pb.HpkeAead_AES_128_GCM:
		return aes128GCM, nil
	case pb.HpkeAead_AES_256_GCM:
		return aes256GCM, nil
	case pb.HpkeAead_CHACHA20_POLY1305:
		return chaCha20Poly1305, nil
	default:
		return 0, fmt.Errorf("HpkeAead enum value %d is not supported", enum)
	}
}
