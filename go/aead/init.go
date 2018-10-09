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
package aead

import (
	"fmt"

	"github.com/google/tink/go/tink"
)

func init() {
	if err := tink.RegisterKeyManager(newAESGCMKeyManager()); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}

	if err := tink.RegisterKeyManager(newChaCha20Poly1305KeyManager()); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}

	if err := tink.RegisterKeyManager(newXChaCha20Poly1305KeyManager()); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %v", err))
	}
}
