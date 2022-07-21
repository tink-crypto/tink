// Copyright 2018 Google LLC
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

package mac

import (
	"fmt"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	intSize = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt  = 1<<(intSize-1) - 1
)

// New creates a MAC primitive from the given keyset handle.
func New(h *keyset.Handle) (tink.MAC, error) {
	return NewWithKeyManager(h, nil /*keyManager*/)
}

// NewWithKeyManager creates a MAC primitive from the given keyset handle and a custom key manager.
// Deprecated: register the KeyManager and use New above.
func NewWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.MAC, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("mac_factory: cannot obtain primitive set: %s", err)
	}

	return newWrappedMAC(ps)
}

// wrappedMAC is a MAC implementation that uses the underlying primitive set to compute and
// verify MACs.
type wrappedMAC struct {
	ps *primitiveset.PrimitiveSet
}

func newWrappedMAC(ps *primitiveset.PrimitiveSet) (*wrappedMAC, error) {
	if _, ok := (ps.Primary.Primitive).(tink.MAC); !ok {
		return nil, fmt.Errorf("mac_factory: not a MAC primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(tink.MAC); !ok {
				return nil, fmt.Errorf("mac_factory: not an MAC primitive")
			}
		}
	}

	ret := new(wrappedMAC)
	ret.ps = ps

	return ret, nil
}

// ComputeMAC calculates a MAC over the given data using the primary primitive
// and returns the concatenation of the primary's identifier and the calculated mac.
func (m *wrappedMAC) ComputeMAC(data []byte) ([]byte, error) {
	primary := m.ps.Primary
	primitive, ok := (primary.Primitive).(tink.MAC)
	if !ok {
		return nil, fmt.Errorf("mac_factory: not a MAC primitive")
	}
	if m.ps.Primary.PrefixType == tinkpb.OutputPrefixType_LEGACY {
		d := data
		if len(d) >= maxInt {
			return nil, fmt.Errorf("mac_factory: data too long")
		}
		data = make([]byte, 0, len(d)+1)
		data = append(data, d...)
		data = append(data, byte(0))
	}
	mac, err := primitive.ComputeMAC(data)
	if err != nil {
		return nil, err
	}
	return append([]byte(primary.Prefix), mac...), nil
}

var errInvalidMAC = fmt.Errorf("mac_factory: invalid mac")

// VerifyMAC verifies whether the given mac is a correct authentication code
// for the given data.
func (m *wrappedMAC) VerifyMAC(mac, data []byte) error {
	// This also rejects raw MAC with size of 4 bytes or fewer. Those MACs are
	// clearly insecure, thus should be discouraged.
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(mac) <= prefixSize {
		return errInvalidMAC
	}

	// try non raw keys
	prefix := mac[:prefixSize]
	macNoPrefix := mac[prefixSize:]
	entries, err := m.ps.EntriesForPrefix(string(prefix))
	if err == nil {
		for i := 0; i < len(entries); i++ {
			entry := entries[i]
			p, ok := (entry.Primitive).(tink.MAC)
			if !ok {
				return fmt.Errorf("mac_factory: not an MAC primitive")
			}
			if entry.PrefixType == tinkpb.OutputPrefixType_LEGACY {
				d := data
				if len(d) >= maxInt {
					return fmt.Errorf("mac_factory: data too long")
				}
				data = make([]byte, 0, len(d)+1)
				data = append(data, d...)
				data = append(data, byte(0))
			}
			if err = p.VerifyMAC(macNoPrefix, data); err == nil {
				return nil
			}
		}
	}

	// try raw keys
	entries, err = m.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			p, ok := (entries[i].Primitive).(tink.MAC)
			if !ok {
				return fmt.Errorf("mac_factory: not an MAC primitive")
			}

			if err = p.VerifyMAC(mac, data); err == nil {
				return nil
			}
		}
	}

	// nothing worked
	return errInvalidMAC
}
