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

package jwt_test

import (
	"testing"

	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestJWTComputeVerifyMAC(t *testing.T) {
	type testCase struct {
		tag     string
		temlate *tinkpb.KeyTemplate
	}
	for _, tc := range []testCase{
		{tag: "JWT_HS256", temlate: jwt.HS256Template()},
		{tag: "JWT_HS384", temlate: jwt.HS384Template()},
		{tag: "JWT_HS512", temlate: jwt.HS512Template()},
		{tag: "JWT_HS256_RAW", temlate: jwt.RawHS256Template()},
		{tag: "JWT_HS384_RAW", temlate: jwt.RawHS384Template()},
		{tag: "JWT_HS512_RAW", temlate: jwt.RawHS512Template()},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			handle, err := keyset.NewHandle(tc.temlate)
			if err != nil {
				t.Errorf("keyset.NewHandle() err = %v, expected nil", err)
			}
			m, err := jwt.NewMAC(handle)
			if err != nil {
				t.Errorf("New() err = %v, expected nil", err)
			}
			rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
			if err != nil {
				t.Errorf("NewRawJWT() err = %v, expected nil", err)
			}
			compact, err := m.ComputeMACAndEncode(rawJWT)
			if err != nil {
				t.Errorf("m.ComputeMACAndEncode() err = %v, expected nil", err)
			}
			verifier, err := jwt.NewJWTValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
			if err != nil {
				t.Errorf("NewJWTValidator() err = %v, expected nil", err)
			}
			if _, err := m.VerifyMACAndDecode(compact, verifier); err != nil {
				t.Errorf("m.VerifyMACAndDecode() err = %v, expected nil", err)
			}
		})
	}
}
