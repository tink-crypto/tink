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

package jwt

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/keyset"
)

// NewSigner generates a new instance of the JWT Signer primitive.
func NewSigner(h *keyset.Handle) (Signer, error) {
	if h == nil {
		return nil, fmt.Errorf("keyset handle can't be nil")
	}
	ps, err := h.PrimitivesWithKeyManager(nil)
	if err != nil {
		return nil, fmt.Errorf("jwt_signer_factory: cannot obtain primitive set: %v", err)
	}
	return newWrappedSigner(ps)
}

// wrappedSigner is a JWT Signer implementation that uses the underlying primitive set for JWT Sign.
type wrappedSigner struct {
	ps *primitiveset.PrimitiveSet
}

var _ Signer = (*wrappedSigner)(nil)

func newWrappedSigner(ps *primitiveset.PrimitiveSet) (*wrappedSigner, error) {
	if _, ok := (ps.Primary.Primitive).(*signerWithKID); !ok {
		return nil, fmt.Errorf("jwt_signer_factory: not a JWT Signer primitive")
	}
	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(*signerWithKID); !ok {
				return nil, fmt.Errorf("jwt_signer_factory: not a JWT Signer primitive")
			}
		}
	}
	return &wrappedSigner{ps: ps}, nil
}

func (w *wrappedSigner) SignAndEncode(rawJWT *RawJWT) (string, error) {
	primary := w.ps.Primary
	p, ok := (primary.Primitive).(*signerWithKID)
	if !ok {
		return "", fmt.Errorf("jwt_signer_factory: not a JWT Signer primitive")
	}
	return p.SignAndEncodeWithKID(rawJWT, keyID(primary.KeyID, primary.PrefixType))
}
