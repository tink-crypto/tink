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
	"time"

	"github.com/google/tink/go/jwt"
)

type validationTestCase struct {
	tag           string
	tokenOpts     *jwt.RawJWTOptions
	validatorOpts *jwt.ValidatorOpts
}

func TestNewValidatorFailure(t *testing.T) {
	for _, tc := range []validationTestCase{
		{
			tag: "combining ExpectedTypeHeader and IgnoreTypeHeader",
			validatorOpts: &jwt.ValidatorOpts{
				ExpectedTypeHeader: refString("should fail"),
				IgnoreTypeHeader:   true,
			},
		},
		{
			tag: "combining ExpectedIssuer and IgnoreIssuer",
			validatorOpts: &jwt.ValidatorOpts{
				ExpectedIssuer: refString("should fail"),
				IgnoreIssuer:   true,
			},
		},
		{
			tag: "combining ExpectedAudiences and IgnoreAudiences",
			validatorOpts: &jwt.ValidatorOpts{
				ExpectedAudiences: refString("should fail"),
				IgnoreAudiences:   true,
			},
		},
		{
			tag: "invalid clock skew",
			validatorOpts: &jwt.ValidatorOpts{
				ClockSkew: time.Minute * 11,
			},
		},
		{
			tag: "validator opts can't be nil",
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			if _, err := jwt.NewJWTValidator(tc.validatorOpts); err == nil {
				t.Errorf("NewJWTValidator(%v) err = nil, want error", tc.validatorOpts)
			}
		})
	}
}

func TestValidationFailures(t *testing.T) {
	for _, tc := range []validationTestCase{
		{
			tag: "expired token",
			tokenOpts: &jwt.RawJWTOptions{
				ExpiresAt: refTime(100),
			},
			validatorOpts: &jwt.ValidatorOpts{
				FixedNow: time.Unix(500, 0),
			},
		},
		{
			tag: "no expiration and AllowMissingExpiration = false",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
			},
			validatorOpts: &jwt.ValidatorOpts{},
		},
		{
			tag: "token expiry equals current time",
			tokenOpts: &jwt.RawJWTOptions{
				ExpiresAt: refTime(123),
			},
			validatorOpts: &jwt.ValidatorOpts{
				FixedNow: time.Unix(123, 0),
			},
		},
		{
			tag: "not before in the future",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				NotBefore:         refTime(1500),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				FixedNow:               time.Unix(1000, 0),
			},
		},
		{
			tag: "issued in the future with ExpectIssuedInThePast = true",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				IssuedAt:          refTime(5000),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				FixedNow:               time.Unix(1000, 0),
				ExpectIssuedInThePast:  true,
			},
		},
		{
			tag: "without issued at with ExpectIssuedInThePast = true",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectIssuedInThePast:  true,
			},
		},
		{
			tag: "no type header and RequiresTypeHeader = true",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectedTypeHeader:     refString("typeHeader"),
			},
		},
		{
			tag: "invalid type header",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				TypeHeader:        refString("typeHeader"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectedTypeHeader:     refString("different"),
			},
		},
		{
			tag: "type header in token but no type header in validator",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				TypeHeader:        refString("typeHeader"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
			},
		},
		{
			tag: "issuer required but not specified",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectedIssuer:         refString("tink-issuer"),
			},
		},
		{
			tag: "invalid issuer",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Issuer:            refString("tink-issuer"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectedIssuer:         refString("different"),
			},
		},
		{
			tag: "issuer in token but not in validator",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Issuer:            refString("issuer"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
			},
		},
		{
			tag: "audience required but no specified",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectedAudiences:      refString("tink-audience"),
			},
		},
		{
			tag: "invalid audience",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Audience:          refString("tink-audience"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectedAudiences:      refString("audience"),
			},
		},
		{
			tag: "audience in token but not in validator",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Audience:          refString("audience"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
			},
		},
	} {

		t.Run(tc.tag, func(t *testing.T) {
			token, err := jwt.NewRawJWT(tc.tokenOpts)
			if err != nil {
				t.Fatalf("jwt.NewRawJWT(%v) err = %v, want nil", tc.tokenOpts, err)
			}
			validator, err := jwt.NewJWTValidator(tc.validatorOpts)
			if err != nil {
				t.Fatalf("jwt.NewJWTValidator(%v) err = %v, want nil", tc.validatorOpts, err)
			}
			if err := validator.Validate(token); err == nil {
				t.Errorf("validator.Validate(%v) err = nil, want error", token)
			}
		})
	}
}

func TestValidationSuccess(t *testing.T) {
	for _, tc := range []validationTestCase{
		{
			tag: "unexpired token",
			tokenOpts: &jwt.RawJWTOptions{
				ExpiresAt: refTime(1000),
			},
			validatorOpts: &jwt.ValidatorOpts{
				FixedNow: time.Unix(100, 0),
			},
		},
		{
			tag: "expired with clock slew",
			tokenOpts: &jwt.RawJWTOptions{
				ExpiresAt: refTime(400),
			},
			validatorOpts: &jwt.ValidatorOpts{
				FixedNow:  time.Unix(500, 0),
				ClockSkew: time.Second * 200,
			},
		},
		{
			tag: "not before in the past",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				NotBefore:         refTime(500),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				FixedNow:               time.Unix(1000, 0),
			},
		},
		{
			tag: "not before equals now",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				NotBefore:         refTime(500),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				FixedNow:               time.Unix(500, 0),
			},
		},
		{
			tag: "not before in near future with clock skew",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				NotBefore:         refTime(600),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				FixedNow:               time.Unix(500, 0),
				ClockSkew:              time.Second * 200,
			},
		},
		{
			tag: "issued in the past",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				IssuedAt:          refTime(500),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				FixedNow:               time.Unix(1000, 0),
			},
		},
		{
			tag: "issued in the future",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				IssuedAt:          refTime(5000),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				FixedNow:               time.Unix(1000, 0),
			},
		},
		{
			tag: "without issued at",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
			},
		},
		{
			tag: "issued in the past with ExpectIssuedInThePast",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				IssuedAt:          refTime(500),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectIssuedInThePast:  true,
				FixedNow:               time.Unix(1000, 0),
			},
		},
		{
			tag: "issued in the past with ExpectIssuedInThePast and clock skew",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				IssuedAt:          refTime(1100),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectIssuedInThePast:  true,
				FixedNow:               time.Unix(1000, 0),
				ClockSkew:              time.Second * 200,
			},
		},
		{

			tag: "expected type header",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				TypeHeader:        refString("typeHeader"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectedTypeHeader:     refString("typeHeader"),
			},
		},
		{
			tag: "ignore type header",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				TypeHeader:        refString("typeHeader"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				IgnoreTypeHeader:       true,
			},
		},
		{
			tag: "expected issuer",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Issuer:            refString("issuer"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectedIssuer:         refString("issuer"),
			},
		},
		{
			tag: "ignore issuer",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Issuer:            refString("issuer"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				IgnoreIssuer:           true,
			},
		},
		{
			tag: "expected audience",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Audience:          refString("audience"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				ExpectedAudiences:      refString("audience"),
			},
		},
		{
			tag: "ignore audience",
			tokenOpts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Audience:          refString("audience"),
			},
			validatorOpts: &jwt.ValidatorOpts{
				AllowMissingExpiration: true,
				IgnoreAudiences:        true,
			},
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			token, err := jwt.NewRawJWT(tc.tokenOpts)
			if err != nil {
				t.Fatalf("NewRawJWT(%v) err = %v, want nil", tc.tokenOpts, err)
			}
			validator, err := jwt.NewJWTValidator(tc.validatorOpts)
			if err != nil {
				t.Fatalf("NewJWTValidator(%v) err = %v, want nil", tc.validatorOpts, err)
			}
			if err := validator.Validate(token); err != nil {
				t.Errorf("validator.Validate(%v) err = %v, want nil", token, err)
			}
		})
	}
}
