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
	"testing"
	"time"

	"github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/tink"
)

func createTinkECVerifier() (tink.Verifier, error) {
	// Public key from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	x, err := base64Decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding x coordinate of public key: %v", err)
	}
	y, err := base64Decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding y coordinate of public key: %v", err)
	}
	tv, err := subtle.NewECDSAVerifier("SHA256", "NIST_P256", "IEEE_P1363", x, y)
	if err != nil {
		return nil, fmt.Errorf("subtle.NewECDSAVerifier() err = %v, want nil", err)
	}
	return tv, nil
}

func createTinkECSigner() (tink.Signer, error) {
	// Private key from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	k, err := base64Decode("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding private key: %v", err)
	}
	ts, err := subtle.NewECDSASigner("SHA256", "NIST_P256", "IEEE_P1363", k)
	if err != nil {
		return nil, fmt.Errorf("subtle.NewECDSASigner() err = %v, want nil", err)
	}
	return ts, nil
}

func createESVerifier(kid *string) (*verifierWithKID, error) {
	tv, err := createTinkECVerifier()
	if err != nil {
		return nil, err
	}
	v, err := newVerifierWithKID(tv, "ES256", kid)
	if err != nil {
		return nil, fmt.Errorf("newVerifierWithKID(algorithm = 'ES256') err = %v, want nil", err)
	}
	return v, nil
}

func createESSigner(kid *string) (*signerWithKID, error) {
	ts, err := createTinkECSigner()
	if err != nil {
		return nil, err
	}
	s, err := newSignerWithKID(ts, "ES256", kid)
	if err != nil {
		return nil, fmt.Errorf("newSignerWithKID(algorithm = 'ES256') err = %v, want nil", err)
	}
	return s, nil
}

func TestVerifierWithFixedToken(t *testing.T) {
	// compact from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	compact := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	v, err := createESVerifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(&ValidatorOpts{ExpectedIssuer: refString("joe"), FixedNow: time.Unix(1300819300, 0)})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	verified, err := v.VerifyAndDecodeWithKID(compact, validator, nil)
	if err != nil {
		t.Errorf("VerifyAndDecodeWithKID() err = %v, want nil", err)
	}
	issuer, err := verified.Issuer()
	if err != nil {
		t.Errorf("verified.Issuer() err = %v, want nil", err)
	}
	if issuer != "joe" {
		t.Errorf("verified.Issuer() = %q, want joe", issuer)
	}
	expiration, err := verified.ExpiresAt()
	if err != nil {
		t.Errorf("verified.ExpiresAt() err = %v, want nil", err)
	}
	wantExp := time.Unix(1300819380, 0)
	if !expiration.Equal(wantExp) {
		t.Errorf("verified.ExpiresAt() = %q, want %q", expiration, wantExp)
	}
	boolClaim, err := verified.BooleanClaim("http://example.com/is_root")
	if err != nil {
		t.Errorf("verified.BooleanClaim('http://example.com/is_root') err = %v, want nil", err)
	}
	if boolClaim != true {
		t.Errorf("verified.BooleanClaim('http://example.com/is_root') = %v, want false", boolClaim)
	}
}

func TestCreateSignValidateToken(t *testing.T) {
	rawJWT, err := NewRawJWT(&RawJWTOptions{TypeHeader: refString("JWT"), WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	validator, err := NewValidator(&ValidatorOpts{ExpectedTypeHeader: refString("JWT"), AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	s, err := createESSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := createESVerifier(nil)
	if err != nil {
		t.Fatal(err)
	}

	compact, err := s.SignAndEncodeWithKID(rawJWT, nil)
	if err != nil {
		t.Fatalf("s.SignAndEncodeWithKID() err = %v, want nil", err)
	}
	verified, err := v.VerifyAndDecodeWithKID(compact, validator, nil)
	if err != nil {
		t.Fatalf("v.VerifyAndDecodeWithKID() err = %v, want nil", err)
	}
	typeHeader, err := verified.TypeHeader()
	if err != nil {
		t.Errorf("verified.TypeHeader() err = %v, want nil", err)
	}
	if typeHeader != "JWT" {
		t.Errorf("verified.TypeHeader() = %q, want 'JWT'", typeHeader)
	}
}

func TestSignerWithTinkAndCustomKIDFails(t *testing.T) {
	rawJWT, err := NewRawJWT(&RawJWTOptions{TypeHeader: refString("JWT"), WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	s, err := createESSigner(refString("1234"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignAndEncodeWithKID(rawJWT, refString("123")); err == nil {
		t.Errorf("s.SignAndEncodeWithKID(kid = 123) err = nil, want error")
	}
}

type signerVerifierKIDTestCase struct {
	tag               string
	signerCustomKID   *string
	verifierCustomKID *string
	// calculated from the Tink Key ID.
	signerKID *string
	// calculated from the Tink Key ID.
	verifierKID *string
}

func TestSignVerifyWithKID(t *testing.T) {
	rawJWT, err := NewRawJWT(&RawJWTOptions{TypeHeader: refString("JWT"), WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	validator, err := NewValidator(&ValidatorOpts{ExpectedTypeHeader: refString("JWT"), AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	for _, tc := range []signerVerifierKIDTestCase{
		{
			tag:               "verifier with custom kid matches kid in header generated with custom kid",
			signerCustomKID:   refString("1234"),
			verifierCustomKID: refString("1234"),
		},
		{
			tag:             "verifier with tink kid matches kid in header generated with custom kid",
			signerCustomKID: refString("1234"),
			verifierKID:     refString("1234"),
		},
		{
			tag:         "verifier with tink kid matches kid in header generated with tink kid",
			signerKID:   refString("1234"),
			verifierKID: refString("1234"),
		},
		{
			tag:       "no kid in verifier ignores kid when present in header",
			signerKID: refString("1234"),
		},
		{
			tag:               "verifier with custom kid ignores when no kid present in header",
			verifierCustomKID: refString("1234"),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			s, err := createESSigner(tc.signerCustomKID)
			if err != nil {
				t.Fatal(err)
			}
			v, err := createESVerifier(tc.verifierCustomKID)
			if err != nil {
				t.Fatal(err)
			}
			compact, err := s.SignAndEncodeWithKID(rawJWT, tc.signerKID)
			if err != nil {
				t.Fatalf("s.SignAndEncodeWithKID(kid = %v) err = %v, want nil", tc.signerKID, err)
			}
			verified, err := v.VerifyAndDecodeWithKID(compact, validator, tc.verifierKID)
			if err != nil {
				t.Fatalf("s.VerifyAndDecodeWithKID(kid = %v) err = %v, want nil", tc.verifierKID, err)
			}
			typeHeader, err := verified.TypeHeader()
			if err != nil {
				t.Errorf("verified.TypeHeader() err = %v, want nil", err)
			}
			if typeHeader != "JWT" {
				t.Errorf("verified.TypeHeader() = %q, want 'JWT'", typeHeader)
			}
		})
	}
}

func TestSignVerifyWithKIDFailure(t *testing.T) {
	rawJWT, err := NewRawJWT(&RawJWTOptions{TypeHeader: refString("JWT"), WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	validator, err := NewValidator(&ValidatorOpts{ExpectedTypeHeader: refString("JWT"), AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	for _, tc := range []signerVerifierKIDTestCase{
		{
			tag:               "verifier with custom kid different from header generated with custom kid",
			signerCustomKID:   refString("1234"),
			verifierCustomKID: refString("123"),
		},
		{
			tag:               "verifier with custom kid different from header generated with tink kid",
			signerKID:         refString("5678"),
			verifierCustomKID: refString("1234"),
		},
		{
			tag:               "verifier with both tink and custom kid",
			verifierCustomKID: refString("1234"),
			verifierKID:       refString("1234"),
		},
		{
			tag:         "verifier with tink kid and token without kid in header",
			verifierKID: refString("1234"),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			s, err := createESSigner(tc.signerCustomKID)
			if err != nil {
				t.Fatal(err)
			}
			v, err := createESVerifier(tc.verifierCustomKID)
			if err != nil {
				t.Fatal(err)
			}
			compact, err := s.SignAndEncodeWithKID(rawJWT, tc.signerKID)
			if err != nil {
				t.Fatalf("s.SignAndEncodeWithKID(kid = %v) err = %v, want nil", tc.signerKID, err)
			}
			if _, err := v.VerifyAndDecodeWithKID(compact, validator, tc.verifierKID); err == nil {
				t.Fatalf("s.VerifyAndDecodeWithKID(kid = %v) err = nil, want error", tc.verifierKID)
			}
		})
	}
}

func TestVerifierModifiedCompact(t *testing.T) {
	rawJWT, err := NewRawJWT(&RawJWTOptions{TypeHeader: refString("JWT"), WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	validator, err := NewValidator(&ValidatorOpts{ExpectedTypeHeader: refString("JWT"), AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	s, err := createESSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := createESVerifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := s.SignAndEncodeWithKID(rawJWT, nil)
	if err != nil {
		t.Fatalf("s.SignAndEncodeWithKID() err = %v, want nil", err)
	}
	if _, err := v.VerifyAndDecodeWithKID(compact, validator, nil); err != nil {
		t.Errorf("VerifyAndDecodeWithKID() err = %v, want nil", err)
	}
	for _, invalid := range []string{
		compact + "x",
		compact + " ",
		"x" + compact,
		" " + compact,
	} {
		if _, err := v.VerifyAndDecodeWithKID(invalid, validator, nil); err == nil {
			t.Errorf("VerifyAndDecodeWithKID() err = nil, want error")
		}
	}
}

func TestVerifierInvalidInputs(t *testing.T) {
	validator, err := NewValidator(&ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	v, err := createESVerifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		"eyJhbGciOiJUzI1NiJ9.e30.YWJj.",
		"eyJhbGciOiJUzI1NiJ9?.e30.YWJj",
		"eyJhbGciOiJUzI1NiJ9.e30?.YWJj",
		"eyJhbGciOiJUzI1NiJ9.e30.YWJj?",
		"eyJhbGciOiJUzI1NiJ9.YWJj",
	} {
		if _, err := v.VerifyAndDecodeWithKID(invalid, validator, nil); err == nil {
			t.Errorf("v.VerifyAndDecodeWithKID(compact = %q) err = nil, want error", invalid)
		}
	}
}

func TestNewSignerWithNilTinkSignerFails(t *testing.T) {
	if _, err := newSignerWithKID(nil, "ES256", nil); err == nil {
		t.Errorf("newSignerWithKID(nil, 'ES256', nil) err = nil, want error")
	}
}

func TestNewVerifierWithNilTinkVerifierFails(t *testing.T) {
	if _, err := newVerifierWithKID(nil, "ES256", nil); err == nil {
		t.Errorf("newVerifierWithKID(nil, 'ES256', nil) err = nil, want error")
	}
}
