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

type signerWithKID struct {
	ts        tink.Signer
	algorithm string
	customKID *string
}

func newSignerWithKID(ts tink.Signer, algorithm string, customKID *string) (*signerWithKID, error) {
	if ts == nil {
		return nil, fmt.Errorf("tink signer can't be nil")
	}
	return &signerWithKID{
		ts:        ts,
		algorithm: algorithm,
		customKID: customKID,
	}, nil
}

// SignAndEncodeWithKID creates the header and content from a rawJWT and combines them into a unsigned token.
// It then signs it and encodes the output using compact serialization.
func (s *signerWithKID) SignAndEncodeWithKID(rawJWT *RawJWT, kid *string) (string, error) {
	unsigned, err := createUnsigned(rawJWT, s.algorithm, kid, s.customKID)
	if err != nil {
		return "", err
	}
	signature, err := s.ts.Sign([]byte(unsigned))
	if err != nil {
		return "", err
	}
	return combineUnsignedAndSignature(unsigned, signature), nil
}
