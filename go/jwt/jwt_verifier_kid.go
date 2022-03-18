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

	"github.com/google/tink/go/tink"
)

type verifierWithKID struct {
	tv        tink.Verifier
	algorithm string
	customKID *string
}

func newVerifierWithKID(tv tink.Verifier, algorithm string, customKID *string) (*verifierWithKID, error) {
	if tv == nil {
		return nil, fmt.Errorf("tink verifier can't be nil")
	}
	return &verifierWithKID{
		tv:        tv,
		algorithm: algorithm,
		customKID: customKID,
	}, nil
}

// VerifyAndDecodeWithKID verifies a digital signature in a compact serialized JWT.
// It then validates the token, and returns a VerifiedJWT or an error.
func (v *verifierWithKID) VerifyAndDecodeWithKID(compact string, validator *Validator, kid *string) (*VerifiedJWT, error) {
	sig, content, err := splitSignedCompact(compact)
	if err != nil {
		return nil, err
	}
	if err := v.tv.Verify(sig, []byte(content)); err != nil {
		return nil, err
	}
	rawJWT, err := decodeUnsignedTokenAndValidateHeader(content, v.algorithm, kid, v.customKID)
	if err != nil {
		return nil, err
	}
	if err := validator.Validate(rawJWT); err != nil {
		return nil, err
	}
	return newVerifiedJWT(rawJWT)
}
