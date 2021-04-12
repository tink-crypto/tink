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

// Package daead provides implementations of the DeterministicAEAD primitive.
//
// Unlike AEAD, implementations of this interface are not semantically secure, because
// encrypting the same plaintex always yields the same ciphertext.
package daead

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

func init() {
	if err := registry.RegisterKeyManager(newAESSIVKeyManager()); err != nil {
		panic(fmt.Sprintf("daead.init() failed: %v", err))
	}
}
