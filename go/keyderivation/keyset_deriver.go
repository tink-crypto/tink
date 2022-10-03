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
////////////////////////////////////////////////////////////////////////////////

// Package keyderivation provides implementations of the keyset deriver
// primitive.
package keyderivation

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
)

// KeysetDeriver is the interface used to derive new keysets based on an
// additional input, the salt.
//
// The salt is used to create the keyset using a pseudorandom function. More
// explicitly, implementations need to generate keysets which are secure even if
// the attacker is given the salt, plus access to an oracle which creates
// keysets for any salt the attacker requests, as long as it is not equal to the
// salt which the attacker attacks.
type KeysetDeriver interface {
	DeriveKeyset(salt []byte) (*keyset.Handle, error)
}

func init() {
	if err := registry.RegisterKeyManager(new(prfBasedDeriverKeyManager)); err != nil {
		panic(fmt.Sprintf("keyderivation.init() failed: %v", err))
	}
}
