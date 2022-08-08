// Copyright 2020 Google LLC
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

package prf

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
)

// NewPRFSet creates a prf.Set primitive from the given keyset handle.
func NewPRFSet(h *keyset.Handle) (*Set, error) {
	return NewPRFSetWithKeyManager(h, nil /*keyManager*/)
}

// NewPRFSetWithKeyManager creates a prf.Set primitive from the given keyset handle and a custom key manager.
//
// Deprecated: Use [New].
func NewPRFSetWithKeyManager(h *keyset.Handle, km registry.KeyManager) (*Set, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("prf_set_factory: cannot obtain primitive set: %s", err)
	}

	return wrapPRFset(ps)
}

func wrapPRFset(ps *primitiveset.PrimitiveSet) (*Set, error) {
	set := &Set{}
	if _, ok := (ps.Primary.Primitive).(PRF); !ok {
		return nil, fmt.Errorf("prf_set_factory: not a PRF primitive")
	}
	set.PrimaryID = ps.Primary.KeyID
	set.PRFs = make(map[uint32]PRF)

	entries, err := ps.RawEntries()
	if err != nil {
		return nil, fmt.Errorf("Could not get raw entries: %v", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("Did not find any raw entries")
	}
	if len(ps.Entries) != 1 {
		return nil, fmt.Errorf("Only raw entries allowed for prf.Set")
	}
	for _, entry := range entries {
		prf, ok := (entry.Primitive).(PRF)
		if !ok {
			return nil, fmt.Errorf("prf_set_factory: not a PRF primitive")
		}
		set.PRFs[entry.KeyID] = prf
	}

	return set, nil
}
