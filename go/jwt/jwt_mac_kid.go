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

	"github.com/google/tink/go/tink"
)

// macWithKID implements the JWTMAC internal interface.
type macWithKID struct {
	tm        tink.MAC
	algorithm string
	customKID *string
}

// newMACWithKID creates a new JWTMACwithKID instance.
func newMACWithKID(tm tink.MAC, algorithm string, customKID *string) (*macWithKID, error) {
	if tm == nil {
		return nil, fmt.Errorf("invalid mac")
	}
	return &macWithKID{
		tm:        tm,
		algorithm: algorithm,
		customKID: customKID,
	}, nil
}

// ComputeMACAndEncodeWithKID computes a MAC over a jwt token and encodes it using compact serialization.
func (jm *macWithKID) ComputeMACAndEncodeWithKID(token *RawJWT, kid *string) (string, error) {
	unsigned, err := createUnsigned(token, jm.algorithm, kid, jm.customKID)
	if err != nil {
		return "", err
	}
	tag, err := jm.tm.ComputeMAC([]byte(unsigned))
	if err != nil {
		return "", err
	}
	return combineUnsignedAndSignature(unsigned, tag), nil
}

// VerifyMACAndDecodeWithKID verifies a MAC in a compact serialized JWT and returns a VerifiedJWT or an error.
func (jm *macWithKID) VerifyMACAndDecodeWithKID(compact string, verifier *Validator, kid *string) (*VerifiedJWT, error) {
	tag, content, err := splitSignedCompact(compact)
	if err != nil {
		return nil, err
	}
	if err := jm.tm.VerifyMAC(tag, []byte(content)); err != nil {
		return nil, err
	}
	rawJWT, err := decodeUnsignedTokenAndValidateHeader(content, jm.algorithm, kid, jm.customKID)
	if err != nil {
		return nil, err
	}
	if err := verifier.Validate(rawJWT); err != nil {
		return nil, err
	}
	return newVerifiedJWT(rawJWT)
}
