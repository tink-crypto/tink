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

// Package aead provides implementations of the AEAD primitive.
//
// AEAD encryption assures the confidentiality and authenticity of the data. This primitive is CPA secure.
package aead

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalapi"
	"github.com/google/tink/go/internal/internalregistry"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// Config is an interface used by key managers and primitive factories to
// represent the relevant Config functionality.
//
// Note that the interface is not public and meant for package-internal use
// only, despite it being exported.
//
// TODO: b/286235179 -- link the implementation.
type Config interface {
	RegisterKeyManager(km registry.KeyManager, t internalapi.Token) error
	PrimitiveFromKeyData(keyData *tinkpb.KeyData, _ internalapi.Token) (any, error)
}

func init() {
	if err := registry.RegisterKeyManager(new(aesCTRHMACAEADKeyManager)); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}

	if err := registry.RegisterKeyManager(new(aesGCMKeyManager)); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}
	if err := internalregistry.AllowKeyDerivation(aesGCMTypeURL); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}

	if err := registry.RegisterKeyManager(new(chaCha20Poly1305KeyManager)); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}

	if err := registry.RegisterKeyManager(new(xChaCha20Poly1305KeyManager)); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}
	if err := internalregistry.AllowKeyDerivation(xChaCha20Poly1305TypeURL); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}

	if err := registry.RegisterKeyManager(new(kmsEnvelopeAEADKeyManager)); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}

	if err := registry.RegisterKeyManager(new(aesGCMSIVKeyManager)); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}
}
