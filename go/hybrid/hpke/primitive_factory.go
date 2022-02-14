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

import "fmt"

// newKEM constructs a HPKE KEM using kemID, which are specified at
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-7.1.
func newKEM(kemID uint16) (kem, error) {
	if kemID == x25519HKDFSHA256 {
		return newX25519KEM(sha256)
	}
	return nil, fmt.Errorf("KEM ID %d is not supported", kemID)
}

// newKDF constructs a HPKE KDF using kdfID, which are specified at
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-7.2.
func newKDF(kdfID uint16) (kdf, error) {
	if kdfID == hkdfSHA256 {
		return newHKDFKDF(sha256)
	}
	return nil, fmt.Errorf("KDF ID %d is not supported", kdfID)
}

// newAEAD constructs a HPKE AEAD using aeadID, which are specified at
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-7.3.
func newAEAD(aeadID uint16) (aead, error) {
	switch aeadID {
	case aes128GCM:
		return newAESGCMAEAD(16)
	case aes256GCM:
		return newAESGCMAEAD(32)
	default:
		return nil, fmt.Errorf("AEAD ID %d is not supported", aeadID)
	}
}
