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
///////////////////////////////////////////////////////////////////////////////

package jwt

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/keyset"
)

// NewVerifier generates a new instance of the JWT Verifier primitive.
func NewVerifier(h *keyset.Handle) (Verifier, error) {
	if h == nil {
		return nil, fmt.Errorf("keyset handle can't be nil")
	}
	ps, err := h.PrimitivesWithKeyManager(nil)
	if err != nil {
		return nil, fmt.Errorf("jwt_verifier_factory: cannot obtain primitive set: %v", err)
	}
	return newWrappedVerifier(ps)
}

// wrappedVerifier is a JWT Verifier implementation that uses the underlying primitive set for JWT Verifier.
type wrappedVerifier struct {
	ps *primitiveset.PrimitiveSet
}

var _ Verifier = (*wrappedVerifier)(nil)

func newWrappedVerifier(ps *primitiveset.PrimitiveSet) (*wrappedVerifier, error) {
	if _, ok := (ps.Primary.Primitive).(*verifierWithKID); !ok {
		return nil, fmt.Errorf("jwt_verifier_factory: not a JWT Verifier primitive")
	}
	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(*verifierWithKID); !ok {
				return nil, fmt.Errorf("jwt_verifier_factory: not a JWT Verifier primitive")
			}
		}
	}
	return &wrappedVerifier{ps: ps}, nil
}

func (w *wrappedVerifier) VerifyAndDecode(compact string, validator *Validator) (*VerifiedJWT, error) {
	for _, s := range w.ps.Entries {
		for _, e := range s {
			p, ok := e.Primitive.(*verifierWithKID)
			if !ok {
				return nil, fmt.Errorf("jwt_verifier_factory: not a JWT Verifier primitive")
			}
			if verifiedJWT, err := p.VerifyAndDecodeWithKID(compact, validator, keyID(e.KeyID, e.PrefixType)); err == nil {
				return verifiedJWT, nil
			}
		}
	}
	return nil, fmt.Errorf("verification failed")
}
