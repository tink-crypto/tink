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

package keyderivation

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var errNotKeysetDeriverPrimitive = errors.New("keyset_deriver_factory: not a Keyset Deriver primitive")

// New generates a new instance of the Keyset Deriver primitive.
func New(h *keyset.Handle) (KeysetDeriver, error) {
	if h == nil {
		return nil, errors.New("keyset_deriver_factory: keyset handle can't be nil")
	}
	ps, err := h.PrimitivesWithKeyManager(nil)
	if err != nil {
		return nil, fmt.Errorf("keyset_deriver_factory: cannot obtain primitive set: %v", err)
	}
	return newWrappedKeysetDeriver(ps)
}

// wrappedKeysetDeriver is a Keyset Deriver implementation that uses the underlying primitive set to derive keysets.
type wrappedKeysetDeriver struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that wrappedKeysetDeriver implements the KeysetDeriver interface.
var _ KeysetDeriver = (*wrappedKeysetDeriver)(nil)

func newWrappedKeysetDeriver(ps *primitiveset.PrimitiveSet) (*wrappedKeysetDeriver, error) {
	if _, ok := (ps.Primary.Primitive).(KeysetDeriver); !ok {
		return nil, errNotKeysetDeriverPrimitive
	}
	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(KeysetDeriver); !ok {
				return nil, errNotKeysetDeriverPrimitive
			}
		}
	}
	return &wrappedKeysetDeriver{ps: ps}, nil
}

func (w *wrappedKeysetDeriver) DeriveKeyset(salt []byte) (*keyset.Handle, error) {
	keys := []*tinkpb.Keyset_Key{}
	for _, entriesWithSamePrefix := range w.ps.Entries {
		for _, e := range entriesWithSamePrefix {
			p, ok := (e.Primitive).(KeysetDeriver)
			if !ok {
				return nil, errNotKeysetDeriverPrimitive
			}
			handle, err := p.DeriveKeyset(salt)
			if err != nil {
				return nil, errors.New("keyset_deriver_factory: keyset derivation failed")
			}
			if len(handle.KeysetInfo().GetKeyInfo()) != 1 {
				return nil, errors.New("keyset_deriver_factory: primitive must derive keyset handle with exactly one key")
			}
			writer := &keyset.MemReaderWriter{}
			if insecurecleartextkeyset.Write(handle, writer) != nil {
				return nil, errors.New("keyset_deriver_factory: failed to retrieve key from derived keyset handle")
			}
			if len(writer.Keyset.GetKey()) != 1 {
				return nil, errors.New("keyset_deriver_factory: primitive must derive keyset handle with exactly one key")
			}
			// Set all fields, except for KeyData, to match the Entry's in the keyset.
			key := &tinkpb.Keyset_Key{
				KeyData:          writer.Keyset.GetKey()[0].GetKeyData(),
				Status:           e.Status,
				KeyId:            e.KeyID,
				OutputPrefixType: e.PrefixType,
			}
			keys = append(keys, key)
		}
	}
	ks := &tinkpb.Keyset{
		PrimaryKeyId: w.ps.Primary.KeyID,
		Key:          keys,
	}
	return insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
}
