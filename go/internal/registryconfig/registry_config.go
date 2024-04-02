// Copyright 2023 Google LLC
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

// Package registryconfig is a transitioning stepping stone used by the
// keyset handle in cases where a configuration is not provided by the user,
// so it needs to resort to using the old global registry methods.
package registryconfig

import (
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalapi"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// RegistryConfig is an internal way for the keyset handle to access the
// old global Regsitry through the new Configuration interface.
type RegistryConfig struct{}

// PrimitiveFromKeyData creates a primitive from KeyData by forwarding the
// KeyData straight to the Registry.
func (c *RegistryConfig) PrimitiveFromKeyData(keyData *tinkpb.KeyData, _ internalapi.Token) (any, error) {
	return registry.PrimitiveFromKeyData(keyData)
}

// RegisterKeyManager registers a provided KeyManager by forwarding it directly
// to the Registry.
func (c *RegistryConfig) RegisterKeyManager(km registry.KeyManager, _ internalapi.Token) error {
	return registry.RegisterKeyManager(km)
}
