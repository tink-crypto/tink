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

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/internal/monitoringutil"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/monitoring"
	"github.com/google/tink/go/tink"
)

// NewHybridEncrypt returns an HybridEncrypt primitive from the given keyset handle.
func NewHybridEncrypt(h *keyset.Handle) (tink.HybridEncrypt, error) {
	ps, err := h.Primitives()
	if err != nil {
		return nil, fmt.Errorf("hybrid_factory: cannot obtain primitive set: %s", err)
	}
	return newEncryptPrimitiveSet(ps)
}

// encryptPrimitiveSet is an HybridEncrypt implementation that uses the underlying primitive set for encryption.
type wrappedHybridEncrypt struct {
	ps     *primitiveset.PrimitiveSet
	logger monitoring.Logger
}

// compile time assertion that wrappedHybridEncrypt implements the HybridEncrypt interface.
var _ tink.HybridEncrypt = (*wrappedHybridEncrypt)(nil)

func newEncryptPrimitiveSet(ps *primitiveset.PrimitiveSet) (*wrappedHybridEncrypt, error) {
	if _, ok := (ps.Primary.Primitive).(tink.HybridEncrypt); !ok {
		return nil, fmt.Errorf("hybrid_factory: not a HybridEncrypt primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(tink.HybridEncrypt); !ok {
				return nil, fmt.Errorf("hybrid_factory: not a HybridEncrypt primitive")
			}
		}
	}
	logger, err := createEncryptLogger(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedHybridEncrypt{
		ps:     ps,
		logger: logger,
	}, nil
}

func createEncryptLogger(ps *primitiveset.PrimitiveSet) (monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, nil
	}
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, err
	}
	return internalregistry.GetMonitoringClient().NewLogger(&monitoring.Context{
		KeysetInfo:  keysetInfo,
		Primitive:   "hybrid_encrypt",
		APIFunction: "encrypt",
	})
}

// Encrypt encrypts the given plaintext binding contextInfo to the resulting ciphertext.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *wrappedHybridEncrypt) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	primary := a.ps.Primary
	p, ok := (primary.Primitive).(tink.HybridEncrypt)
	if !ok {
		return nil, fmt.Errorf("hybrid_factory: not a HybridEncrypt primitive")
	}

	ct, err := p.Encrypt(plaintext, contextInfo)
	if err != nil {
		a.logger.LogFailure()
		return nil, err
	}
	a.logger.Log(primary.KeyID, len(plaintext))
	return append([]byte(primary.Prefix), ct...), nil
}
