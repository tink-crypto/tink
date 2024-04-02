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

package keyderivation

import (
	"github.com/google/tink/go/keyset"
)

// KeysetDeriver is the interface used to derive new keysets based on an
// additional input, the salt.
//
// The salt is used to create the keyset using a pseudorandom function.
// Implementations must be indistinguishable from ideal KeysetDerivers, which,
// for every salt, generates a new random keyset and caches it.
type KeysetDeriver interface {
	DeriveKeyset(salt []byte) (*keyset.Handle, error)
}
