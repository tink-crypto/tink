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

type templateTestCase struct {
	tag      string
	template *tinkpb.KeyTemplate
}

func TestJWTComputeVerifyMAC(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Errorf("NewRawJWT() err = %v, want nil", err)
	}
	for _, tc := range []templateTestCase{
		{tag: "JWT_HS256", template: jwt.HS256Template()},
		{tag: "JWT_HS384", template: jwt.HS384Template()},
		{tag: "JWT_HS512", template: jwt.HS512Template()},
		{tag: "JWT_HS256_RAW", template: jwt.RawHS256Template()},
		{tag: "JWT_HS384_RAW", template: jwt.RawHS384Template()},
		{tag: "JWT_HS512_RAW", template: jwt.RawHS512Template()},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				t.Errorf("keyset.NewHandle() err = %v, want nil", err)
			}
			m, err := jwt.NewMAC(handle)
			if err != nil {
				t.Errorf("New() err = %v, want nil", err)
			}
			compact, err := m.ComputeMACAndEncode(rawJWT)
			if err != nil {
				t.Errorf("m.ComputeMACAndEncode() err = %v, want nil", err)
			}
			verifier, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
			if err != nil {
				t.Errorf("NewValidator() err = %v, want nil", err)
			}
			if _, err := m.VerifyMACAndDecode(compact, verifier); err != nil {
				t.Errorf("m.VerifyMACAndDecode() err = %v, want nil", err)
			}
		})
	}
}

func TestJWTSignVerifyECDSA(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	for _, tc := range []templateTestCase{
		{tag: "JWT_ES256", template: jwt.ES256Template()},
		{tag: "JWT_ES384", template: jwt.ES384Template()},
		{tag: "JWT_ES512", template: jwt.ES512Template()},
		{tag: "JWT_ES256_RAW", template: jwt.RawES256Template()},
		{tag: "JWT_ES384_RAW", template: jwt.RawES384Template()},
		{tag: "JWT_ES512_RAW", template: jwt.RawES512Template()},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			kh, err := keyset.NewHandle(tc.template)
			if err != nil {
				t.Errorf("keyset.NewHandle() err = %v, want nil", err)
			}
			signer, err := jwt.NewSigner(kh)
			if err != nil {
				t.Errorf("jwt.NewSigner() err = %v, want nil", err)
			}
			compact, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
			}
			pubkh, err := kh.Public()
			if err != nil {
				t.Fatalf("key handle Public() err = %v, want nil", err)
			}
			verifier, err := jwt.NewVerifier(pubkh)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
			if err != nil {
				t.Fatalf("jwt.NewJWTValidator() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}
		})
	}
}
