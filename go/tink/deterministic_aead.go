// Copyright 2018 Google LLC
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

package tink

/*
DeterministicAEAD is the interface for deterministic authenticated encryption with associated data.

Warning:
Unlike AEAD, implementations of this interface are not semantically secure, because
encrypting the same plaintext always yields the same ciphertext.

Security guarantees:
Implementations of this interface provide 128-bit security level against multi-user attacks
with up to 2^32 keys. That means if an adversary obtains 2^32 ciphertexts of the same message
encrypted under 2^32 keys, they need to do 2^128 computations to obtain a single key.

Encryption with associated data ensures authenticity (who the sender is) and integrity (the
data has not been tampered with) of that data, but not its secrecy.

References:
https://tools.ietf.org/html/rfc5116
https://tools.ietf.org/html/rfc5297#section-1.3
*/
type DeterministicAEAD interface {
	// EncryptDeterministically deterministically encrypts plaintext with associatedData as
	// associated authenticated data.
	//
	// Warning:
	// Encrypting the same plaintext multiple times protects the integrity of that plaintext,
	// but confidentiality is compromised to the extent that an attacker can determine that
	// the same plaintext was encrypted.
	//
	// The resulting ciphertext allows for checking authenticity and integrity of associatedData,
	// but does not guarantee its secrecy.
	EncryptDeterministically(plaintext, associatedData []byte) ([]byte, error)

	// DecryptDeterministically deterministically decrypts ciphertext with associatedData as
	// associated authenticated data. The decryption verifies the authenticity and integrity
	// of the associated data, but there are no guarantees with respect to secrecy of that data.
	DecryptDeterministically(ciphertext, associatedData []byte) ([]byte, error)
}
