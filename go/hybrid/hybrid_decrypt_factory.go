// Copyright 2019 Google LLC
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

package hybrid

import (
	"fmt"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/internal/monitoringutil"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/monitoring"
	"github.com/google/tink/go/tink"
)

// NewHybridDecrypt returns an HybridDecrypt primitive from the given keyset handle.
func NewHybridDecrypt(h *keyset.Handle) (tink.HybridDecrypt, error) {
	ps, err := h.Primitives()
	if err != nil {
		return nil, fmt.Errorf("hybrid_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedHybridDecrypt(ps)
}

// wrappedHybridDecrypt is an HybridDecrypt implementation that uses the underlying primitive set
// for decryption.
type wrappedHybridDecrypt struct {
	ps     *primitiveset.PrimitiveSet
	logger monitoring.Logger
}

// compile time assertion that wrappedHybridDecrypt implements the HybridDecrypt interface.
var _ tink.HybridDecrypt = (*wrappedHybridDecrypt)(nil)

func newWrappedHybridDecrypt(ps *primitiveset.PrimitiveSet) (*wrappedHybridDecrypt, error) {
	if _, ok := (ps.Primary.Primitive).(tink.HybridDecrypt); !ok {
		return nil, fmt.Errorf("hybrid_factory: not a HybridDecrypt primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(tink.HybridDecrypt); !ok {
				return nil, fmt.Errorf("hybrid_factory: not a HybridDecrypt primitive")
			}
		}
	}
	logger, err := createDecryptLogger(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedHybridDecrypt{
		ps:     ps,
		logger: logger,
	}, nil
}

func createDecryptLogger(ps *primitiveset.PrimitiveSet) (monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, nil
	}
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, err
	}
	return internalregistry.GetMonitoringClient().NewLogger(&monitoring.Context{
		KeysetInfo:  keysetInfo,
		Primitive:   "hybrid_decrypt",
		APIFunction: "decrypt",
	})
}

// Decrypt decrypts the given ciphertext, verifying the integrity of contextInfo.
// It returns the corresponding plaintext if the ciphertext is authenticated.
func (a *wrappedHybridDecrypt) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	// try non-raw keys
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(ciphertext) > prefixSize {
		prefix := ciphertext[:prefixSize]
		ctNoPrefix := ciphertext[prefixSize:]
		entries, err := a.ps.EntriesForPrefix(string(prefix))
		if err == nil {
			for i := 0; i < len(entries); i++ {
				p, ok := (entries[i].Primitive).(tink.HybridDecrypt)
				if !ok {
					return nil, fmt.Errorf("hybrid_factory: not a HybridDecrypt primitive")
				}

				pt, err := p.Decrypt(ctNoPrefix, contextInfo)
				if err == nil {
					a.logger.Log(entries[i].KeyID, len(ctNoPrefix))
					return pt, nil
				}
			}
		}
	}

	// try raw keys
	entries, err := a.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			p, ok := (entries[i].Primitive).(tink.HybridDecrypt)
			if !ok {
				return nil, fmt.Errorf("hybrid_factory: not a HybridDecrypt primitive")
			}

			pt, err := p.Decrypt(ciphertext, contextInfo)
			if err == nil {
				a.logger.Log(entries[i].KeyID, len(ciphertext))
				return pt, nil
			}
		}
	}

	// nothing worked
	a.logger.LogFailure()
	return nil, fmt.Errorf("hybrid_factory: decryption failed")
}
