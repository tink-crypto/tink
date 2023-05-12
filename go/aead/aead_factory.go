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
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/internal/monitoringutil"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/monitoring"
	"github.com/google/tink/go/tink"
)

// New returns an AEAD primitive from the given keyset handle.
func New(h *keyset.Handle) (tink.AEAD, error) {
	ps, err := h.Primitives()
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
	encLogger, decLogger, err := createLoggers(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedAead{
		ps:        ps,
		encLogger: encLogger,
		decLogger: decLogger,
	}, nil
}

func createLoggers(ps *primitiveset.PrimitiveSet) (monitoring.Logger, monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, &monitoringutil.DoNothingLogger{}, nil
	}
	client := internalregistry.GetMonitoringClient()
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, nil, err
	}
	encLogger, err := client.NewLogger(&monitoring.Context{
		Primitive:   "aead",
		APIFunction: "encrypt",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, nil, err
	}
	decLogger, err := client.NewLogger(&monitoring.Context{
		Primitive:   "aead",
		APIFunction: "decrypt",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, nil, err
	}
	return encLogger, decLogger, nil
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
		a.encLogger.LogFailure()
		return nil, err
	}
	a.encLogger.Log(primary.KeyID, len(plaintext))
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
					a.decLogger.Log(entries[i].KeyID, len(ctNoPrefix))
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
				a.decLogger.Log(entries[i].KeyID, len(ciphertext))
				return pt, nil
			}
		}
	}
	// nothing worked
	a.decLogger.LogFailure()
	return nil, fmt.Errorf("aead_factory: decryption failed")
}
