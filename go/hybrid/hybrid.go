// Copyright 2019 Google LLC
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

// Package hybrid provides subtle implementations of the HKDF and EC primitives.
//
// The functionality of Hybrid Encryption is represented as a pair of
// primitives (interfaces):
//
//  * HybridEncrypt for encryption of data
//
//  * HybridDecrypt for decryption of data
//
// Implementations of these interfaces are secure against adaptive chosen
// ciphertext attacks. In addition to plaintext the encryption takes an extra
// parameter contextInfo, which usually is public data implicit from the
// context, but should be bound to the resulting ciphertext, i.e. the
// ciphertext allows for checking the integrity of contextInfo (but there are
// no guarantees wrt. the secrecy or authenticity of contextInfo).
package hybrid

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

func init() {
	if err := registry.RegisterKeyManager(new(hpkePublicKeyManager)); err != nil {
		panic(fmt.Sprintf("hybrid.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(hpkePrivateKeyManager)); err != nil {
		panic(fmt.Sprintf("hybrid.init() failed: %v", err))
	}

	if err := registry.RegisterKeyManager(new(eciesAEADHKDFPrivateKeyKeyManager)); err != nil {
		panic(fmt.Sprintf("hybrid.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(eciesAEADHKDFPublicKeyKeyManager)); err != nil {
		panic(fmt.Sprintf("hybrid.init() failed: %v", err))
	}
}
