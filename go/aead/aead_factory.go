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

package aead

import (
	"fmt"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/internal/monitoringutil"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/monitoring"
	"github.com/google/tink/go/tink"
)

// New returns an AEAD primitive from the given keyset handle.
func New(h *keyset.Handle) (tink.AEAD, error) {
	return NewWithKeyManager(h, nil /*keyManager*/)
}

// NewWithKeyManager returns an AEAD primitive from the given keyset handle and custom key manager.
// Deprecated: register the KeyManager and use New above.
func NewWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.AEAD, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("aead_factory: cannot obtain primitive set: %s", err)
	}

	return newWrappedAead(ps)
}

// wrappedAead is an AEAD implementation that uses the underlying primitive set for encryption
// and decryption.
type wrappedAead struct {
	ps        *primitiveset.PrimitiveSet
	encLogger monitoring.Logger
	decLogger monitoring.Logger
}

func newWrappedAead(ps *primitiveset.PrimitiveSet) (*wrappedAead, error) {
	if _, ok := (ps.Primary.Primitive).(tink.AEAD); !ok {
		return nil, fmt.Errorf("aead_factory: not an AEAD primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(tink.AEAD); !ok {
				return nil, fmt.Errorf("aead_factory: not an AEAD primitive")
			}
		}
	}
	wa := &wrappedAead{ps: ps}
	client := internalregistry.GetMonitoringClient()
	if client == nil {
		return wa, nil
	}
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, err
	}
	wa.encLogger, err = client.NewLogger(&monitoring.Context{
		Primitive:   "aead",
		APIFunction: "encrypt",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, err
	}
	wa.decLogger, err = client.NewLogger(&monitoring.Context{
		Primitive:   "aead",
		APIFunction: "decrypt",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, err
	}
	return wa, nil
}

// Encrypt encrypts the given plaintext with the given associatedData.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *wrappedAead) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	primary := a.ps.Primary
	p, ok := (primary.Primitive).(tink.AEAD)
	if !ok {
		return nil, fmt.Errorf("aead_factory: not an AEAD primitive")
	}
	ct, err := p.Encrypt(plaintext, associatedData)
	if err != nil {
		if a.encLogger != nil {
			a.encLogger.LogFailure()
		}
		return nil, err
	}
	if a.encLogger != nil {
		a.encLogger.Log(primary.KeyID, len(plaintext))
	}
	return append([]byte(primary.Prefix), ct...), nil
}

// Decrypt decrypts the given ciphertext and authenticates it with the given
// associatedData. It returns the corresponding plaintext if the
// ciphertext is authenticated.
func (a *wrappedAead) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	// try non-raw keys
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(ciphertext) > prefixSize {
		prefix := ciphertext[:prefixSize]
		ctNoPrefix := ciphertext[prefixSize:]
		entries, err := a.ps.EntriesForPrefix(string(prefix))
		if err == nil {
			for i := 0; i < len(entries); i++ {
				p, ok := (entries[i].Primitive).(tink.AEAD)
				if !ok {
					return nil, fmt.Errorf("aead_factory: not an AEAD primitive")
				}

				pt, err := p.Decrypt(ctNoPrefix, associatedData)
				if err == nil {
					if a.decLogger != nil {
						a.decLogger.Log(entries[i].KeyID, len(ctNoPrefix))
					}
					return pt, nil
				}
			}
		}
	}
	// try raw keys
	entries, err := a.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			p, ok := (entries[i].Primitive).(tink.AEAD)
			if !ok {
				return nil, fmt.Errorf("aead_factory: not an AEAD primitive")
			}

			pt, err := p.Decrypt(ciphertext, associatedData)
			if err == nil {
				if a.decLogger != nil {
					a.decLogger.Log(entries[i].KeyID, len(ciphertext))
				}
				return pt, nil
			}
		}
	}
	// nothing worked
	if a.decLogger != nil {
		a.decLogger.LogFailure()
	}
	return nil, fmt.Errorf("aead_factory: decryption failed")
}
