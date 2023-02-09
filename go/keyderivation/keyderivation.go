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
//
// # Status
//
// This package is not completely implemented.
// TODO(b/227682336): Add cross-language tests before modifying status.
package keyderivation

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var (
	keysetHandle   = internal.KeysetHandle.(func(*tinkpb.Keyset, ...keyset.Option) (*keyset.Handle, error))
)

func init() {
	if err := registry.RegisterKeyManager(new(prfBasedDeriverKeyManager)); err != nil {
		panic(fmt.Sprintf("keyderivation.init() failed: %v", err))
	}
}
