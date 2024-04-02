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

// Package signature provides implementations of the Signer and Verifier
// primitives.
//
// To sign data using Tink you can use ECDSA, ED25519 or RSA-SSA-PKCS1 key templates.
package signature

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalregistry"
)

func init() {
	// ECDSA
	if err := registry.RegisterKeyManager(new(ecdsaSignerKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(ecdsaVerifierKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}

	// ED25519
	if err := registry.RegisterKeyManager(new(ed25519SignerKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
	if err := internalregistry.AllowKeyDerivation(ed25519SignerTypeURL); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(ed25519VerifierKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}

	// RSA SSA PKCS1
	if err := registry.RegisterKeyManager(new(rsaSSAPKCS1SignerKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(rsaSSAPKCS1VerifierKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}

	// RSA SSA PSS
	if err := registry.RegisterKeyManager(new(rsaSSAPSSSignerKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(rsaSSAPSSVerifierKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
}
