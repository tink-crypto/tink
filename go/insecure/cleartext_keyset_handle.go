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

// Package insecure provides functions that create KeysetHandle from cleartext key material.
//
// This package contains dangerous functions, and is separate from the rest of Tink so that its
// usage can be restricted and audited.
package insecure

import (
	"errors"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/internal"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

var keysetHandle = internal.KeysetHandle.(func(*tinkpb.Keyset) *tink.KeysetHandle)

var errInvalidKeyset = errors.New("keyset_handle: invalid keyset")

// KeysetHandleFromSerializedProto creates a new instance of KeysetHandle from the given
// serialized keyset proto.
func KeysetHandleFromSerializedProto(serialized []byte) (*tink.KeysetHandle, error) {
	if len(serialized) == 0 {
		return nil, errInvalidKeyset
	}
	ks := new(tinkpb.Keyset)
	if err := proto.Unmarshal(serialized, ks); err != nil {
		return nil, errInvalidKeyset
	}
	return keysetHandle(ks), nil
}

// KeysetHandle creates a new instance of KeysetHandle using the given keyset.
func KeysetHandle(ks *tinkpb.Keyset) (*tink.KeysetHandle, error) {
	if ks == nil || len(ks.Key) == 0 {
		return nil, errInvalidKeyset
	}
	return keysetHandle(ks), nil
}
