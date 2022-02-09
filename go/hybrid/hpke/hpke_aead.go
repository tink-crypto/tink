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

// hpkeAead is a package-internal interface for the Hybrid Public Key
// Encryption (HPKE) authenticated encryption with associated data (AEAD).
//
// The HPKE I-D is available at
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html.
type hpkeAead interface {
	// seal performs authenticated encryption of plaintext and associatedData
	// using key and nonce.
	//
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#name-encryption-and-decryption
	seal(key, nonce, plaintext, associatedData []byte) ([]byte, error)

	// open performs authenticated decryption of ciphertext and associatedData
	// using key and nonce.
	//
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#name-encryption-and-decryption
	open(key, nonce, ciphertext, associatedData []byte) ([]byte, error)

	// aeadID returns the HPKE AEAD algorithm identifier for the underlying AEAD
	// implementation.
	//
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#name-aead-identifiers
	aeadID() uint16
}
