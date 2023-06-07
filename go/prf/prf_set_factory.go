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
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/internal/monitoringutil"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/monitoring"
)

// NewPRFSet creates a prf.Set primitive from the given keyset handle.
func NewPRFSet(handle *keyset.Handle) (*Set, error) {
	ps, err := handle.Primitives()
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
	logger, err := createLogger(ps)
	if err != nil {
		return nil, err
	}
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
		set.PRFs[entry.KeyID] = &monitoredPRF{
			prf:    prf,
			keyID:  entry.KeyID,
			logger: logger,
		}
	}
	return set, nil
}

func createLogger(ps *primitiveset.PrimitiveSet) (monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, nil
	}
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, err
	}
	return internalregistry.GetMonitoringClient().NewLogger(&monitoring.Context{
		KeysetInfo:  keysetInfo,
		Primitive:   "prf",
		APIFunction: "compute",
	})
}
