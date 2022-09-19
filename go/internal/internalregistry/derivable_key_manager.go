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

package internalregistry

import (
	"io"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// DerivableKeyManager is a special type of KeyManager that can derive new keys.
type DerivableKeyManager interface {
	registry.KeyManager

	// KeyMaterialType returns the key material type of the key manager.
	KeyMaterialType() tinkpb.KeyData_KeyMaterialType

	// DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
	//
	// Note: The given parameter pseudorandomness may only produce a finite amount
	// of randomness. Implementions must obtain the pseudorandom bytes needed
	// before producing the key.
	DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error)
}
