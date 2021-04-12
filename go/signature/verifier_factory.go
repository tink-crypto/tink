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

package signature

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// NewVerifier returns a Verifier primitive from the given keyset handle.
func NewVerifier(h *keyset.Handle) (tink.Verifier, error) {
	return NewVerifierWithKeyManager(h, nil /*keyManager*/)
}

// NewVerifierWithKeyManager returns a Verifier primitive from the given keyset handle and custom key manager.
// Deprecated: register the KeyManager and use New above.
func NewVerifierWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.Verifier, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("verifier_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedVerifier(ps)
}

// verifierSet is a Verifier implementation that uses the
// underlying primitive set for verifying.
type wrappedVerifier struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that verifierSet implements the Verifier interface.
var _ tink.Verifier = (*wrappedVerifier)(nil)

func newWrappedVerifier(ps *primitiveset.PrimitiveSet) (*wrappedVerifier, error) {
	if _, ok := (ps.Primary.Primitive).(tink.Verifier); !ok {
		return nil, fmt.Errorf("verifier_factory: not a Verifier primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(tink.Verifier); !ok {
				return nil, fmt.Errorf("verifier_factory: not an Verifier primitive")
			}
		}
	}

	ret := new(wrappedVerifier)
	ret.ps = ps

	return ret, nil
}

var errInvalidSignature = errors.New("verifier_factory: invalid signature")

// Verify checks whether the given signature is a valid signature of the given data.
func (v *wrappedVerifier) Verify(signature, data []byte) error {
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(signature) < prefixSize {
		return errInvalidSignature
	}

	// try non-raw keys
	prefix := signature[:prefixSize]
	signatureNoPrefix := signature[prefixSize:]
	entries, err := v.ps.EntriesForPrefix(string(prefix))
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var signedData []byte
			if entries[i].PrefixType == tinkpb.OutputPrefixType_LEGACY {
				signedData = append(data, byte(0))
			} else {
				signedData = data
			}

			verifier, ok := (entries[i].Primitive).(tink.Verifier)
			if !ok {
				return fmt.Errorf("verifier_factory: not an Verifier primitive")
			}

			if err = verifier.Verify(signatureNoPrefix, signedData); err == nil {
				return nil
			}
		}
	}

	// try raw keys
	entries, err = v.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			verifier, ok := (entries[i].Primitive).(tink.Verifier)
			if !ok {
				return fmt.Errorf("verifier_factory: not an Verifier primitive")
			}

			if err = verifier.Verify(signature, data); err == nil {
				return nil
			}
		}
	}

	return errInvalidSignature
}
