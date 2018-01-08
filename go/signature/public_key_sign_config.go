// Copyright 2017 Google Inc.
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

package signature

import (
	"github.com/google/tink/go/tink/tink"
	"sync"
)

// PublicKeySignConfig contains convenience methods for initializing the Registry with native
// key types and their managers that Tink supports out of the box.
// These key types are divided in two groups:
//    - standard: secure and safe to use in new code. Over time, with new developments in
//               cryptanalysis and computing power, some standard key types might become legacy.
//    - legacy: deprecated and insecure or obsolete, should not be used in new code.
//              Existing users should upgrade to one of the standard key types.
// This divison allows for gradual retiring insecure or obsolete key types.

// publicKeySignConfigInstance is a shared instance of publicKeySignConfig.
// It is initialized only once via function PublicKeySignConfig().
var publicKeySignConfigInstance *publicKeySignConfig
var publicKeySignConfigOnce sync.Once

type publicKeySignConfig struct{}

// PublicKeySignConfig creates an instance of publicKeySignConfig if there isn't
// and returns the instance.
func PublicKeySignConfig() *publicKeySignConfig {
	publicKeySignConfigOnce.Do(func() {
		publicKeySignConfigInstance = new(publicKeySignConfig)
	})
	return publicKeySignConfigInstance
}

// RegisterStandardKeyTypes registers standard Aead key types and their managers
// with the Registry.
func (c *publicKeySignConfig) RegisterStandardKeyTypes() (bool, error) {
	return c.RegisterKeyManager(NewEcdsaSignKeyManager())
}

// RegisterLegacyKeyTypes registers legacy Aead key types and their managers
// with the Registry.
func (c *publicKeySignConfig) RegisterLegacyKeyTypes() (bool, error) {
	return false, nil
}

// RegisterKeyManager registers the given keyManager for the key type given in
// keyManager.KeyType(). It returns true if registration was successful, false if
// there already exisits a key manager for the key type.
func (c *publicKeySignConfig) RegisterKeyManager(keyManager tink.KeyManager) (bool, error) {
	return tink.Registry().RegisterKeyManager(keyManager)
}
