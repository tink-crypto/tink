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

// NewMAC generates a new instance of the JWT MAC primitive.
func NewMAC(h *keyset.Handle) (MAC, error) {
	if h == nil {
		return nil, fmt.Errorf("keyset handle can't be nil")
	}
	ps, err := h.PrimitivesWithKeyManager(nil)
	if err != nil {
		return nil, fmt.Errorf("jwt_mac_factory: cannot obtain primitive set: %v", err)
	}
	return newWrappedJWTMAC(ps)
}

// wrappedJWTMAC is a JWTMAC implementation that uses the underlying primitive set for JWT MAC.
type wrappedJWTMAC struct {
	ps *primitiveset.PrimitiveSet
}

var _ MAC = (*wrappedJWTMAC)(nil)

func newWrappedJWTMAC(ps *primitiveset.PrimitiveSet) (*wrappedJWTMAC, error) {
	if _, ok := (ps.Primary.Primitive).(*macWithKID); !ok {
		return nil, fmt.Errorf("jwt_mac_factory: not a JWT MAC primitive")
	}
	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(*macWithKID); !ok {
				return nil, fmt.Errorf("jwt_mac_factory: not a JWT MAC primitive")
			}
		}
	}
	return &wrappedJWTMAC{ps: ps}, nil
}

func (w *wrappedJWTMAC) ComputeMACAndEncode(token *RawJWT) (string, error) {
	primary := w.ps.Primary
	p, ok := (primary.Primitive).(*macWithKID)
	if !ok {
		return "", fmt.Errorf("jwt_mac_factory: not a JWT MAC primitive")
	}
	return p.ComputeMACAndEncodeWithKID(token, keyID(primary.KeyID, primary.PrefixType))
}

func (w *wrappedJWTMAC) VerifyMACAndDecode(compact string, validator *Validator) (*VerifiedJWT, error) {
	for _, s := range w.ps.Entries {
		for _, e := range s {
			p, ok := e.Primitive.(*macWithKID)
			if !ok {
				return nil, fmt.Errorf("jwt_mac_factory: not a JWT MAC primitive")
			}
			if verifiedJWT, err := p.VerifyMACAndDecodeWithKID(compact, validator, keyID(e.KeyID, e.PrefixType)); err == nil {
				return verifiedJWT, nil
			}
		}
	}
	return nil, fmt.Errorf("verification failed")
}
