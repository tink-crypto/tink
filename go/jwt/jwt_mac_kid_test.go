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
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/google/tink/go/mac/subtle"
)

func TestNewMACwithNilMACFails(t *testing.T) {
	if _, err := newMACWithKID(nil, "", nil); err == nil {
		t.Errorf("NewMACWithKID(nil, '', nil) err = nil, want error")
	}
}

func createMACwithKID(customKID *string) (*macWithKID, error) {
	// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
	key, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
	if err != nil {
		return nil, fmt.Errorf("failed parsing test key: %v", err)
	}
	mac, err := subtle.NewHMAC("SHA256", key, 32)
	if err != nil {
		return nil, err
	}
	return newMACWithKID(mac, "HS256", customKID)
}

func TestCreateAndValidateToken(t *testing.T) {
	m, err := createMACwithKID(nil)
	if err != nil {
		t.Fatalf("creating JWTMACwithKID primitive: %v", err)
	}
	rawOpts := &RawJWTOptions{
		TypeHeader:        refString("typeHeader"),
		JWTID:             refString("123"),
		WithoutExpiration: true,
	}
	rawJWT, err := NewRawJWT(rawOpts)
	if err != nil {
		t.Errorf("NewRawJWT() err = %v, want nil", err)
	}
	compact, err := m.ComputeMACAndEncodeWithKID(rawJWT, nil)
	if err != nil {
		t.Errorf("m.ComputeMACAndEncodeWithKID err = %v, want nil", err)
	}
	validatorOps := &ValidatorOpts{
		ExpectedTypeHeader:     refString("typeHeader"),
		AllowMissingExpiration: true,
	}
	validator, err := NewJWTValidator(validatorOps)
	if err != nil {
		t.Errorf("NewJWTValidator err = %v, want nil", err)
	}
	verifiedJWT, err := m.VerifyMACAndDecodeWithKID(compact, validator, nil)
	if err != nil {
		t.Errorf("m.VerifyMACAndDecodeWithKID() err = %v, want nil", err)
	}
	typeHeader, err := verifiedJWT.TypeHeader()
	if err != nil {
		t.Errorf("verifiedJWT.TypeHeader() err = %v, want nil", err)
	}
	if typeHeader != "typeHeader" {
		t.Errorf("verifiedJWT.TypeHeader() = %q, want 'typeHeader'", typeHeader)
	}
	jwtID, err := verifiedJWT.JWTID()
	if err != nil {
		t.Errorf("verifiedJWT.JWTID() err = %v, want nil", err)
	}
	if jwtID != "123" {
		t.Errorf("verifiedJWT.JWTID() = %q, want '123'", jwtID)
	}

	validatorOps = &ValidatorOpts{
		ExpectedTypeHeader:     refString("notTypeHeader"),
		AllowMissingExpiration: true,
	}
	validator, err = NewJWTValidator(validatorOps)
	if err != nil {
		t.Errorf("NewJWTValidator err = %v, want nil", err)
	}
	if _, err := m.VerifyMACAndDecodeWithKID(compact, validator, nil); err == nil {
		t.Errorf("m.VerifyMACAndDecodeWithKID() err = nil, want error")
	}
}

func TestCreateAndValidateTokenWithKID(t *testing.T) {
	m, err := createMACwithKID(nil)
	if err != nil {
		t.Fatalf("creating JWTMACwithKID primitive: %v", err)
	}
	rawOpts := &RawJWTOptions{
		TypeHeader:        refString("typeHeader"),
		JWTID:             refString("123"),
		WithoutExpiration: true,
	}
	rawJWT, err := NewRawJWT(rawOpts)
	if err != nil {
		t.Errorf("NewRawJWT() err = %v, want nil", err)
	}
	compact, err := m.ComputeMACAndEncodeWithKID(rawJWT, refString("kid-123"))
	if err != nil {
		t.Errorf("m.ComputeMACAndEncodeWithKID err = %v, want nil", err)
	}
	opts := &ValidatorOpts{
		ExpectedTypeHeader:     refString("typeHeader"),
		AllowMissingExpiration: true,
	}
	validator, err := NewJWTValidator(opts)
	if err != nil {
		t.Fatalf("creating JWT validator, NewJWTValidator: %v", err)
	}
	verifiedJWT, err := m.VerifyMACAndDecodeWithKID(compact, validator, refString("kid-123"))
	if err != nil {
		t.Errorf("m.VerifyMACAndDecodeWithKID(kid = kid-123) err = %v, want nil", err)
	}

	typeHeader, err := verifiedJWT.TypeHeader()
	if err != nil {
		t.Errorf("verifiedJWT.TypeHeader() err = %v, want nil", err)
	}
	if typeHeader != *rawOpts.TypeHeader {
		t.Errorf("verifiedJWT.TypeHeader() = %q, want %q", typeHeader, *rawOpts.TypeHeader)
	}
	jwtID, err := verifiedJWT.JWTID()
	if err != nil {
		t.Errorf("verifiedJWT.JWTID() err = %v, want nil", err)
	}
	if jwtID != *rawOpts.JWTID {
		t.Errorf("verifiedJWT.JWTID() = %q, want %q", jwtID, *rawOpts.JWTID)
	}

	if _, err := m.VerifyMACAndDecodeWithKID(compact, validator, nil); err != nil {
		t.Errorf("m.VerifyMACAndDecodeWithKID(kid = nil) err = %v, want nil", err)
	}
	if _, err := m.VerifyMACAndDecodeWithKID(compact, validator, refString("other-kid")); err == nil {
		t.Errorf("m.VerifyMACAndDecodeWithKID(kid = 'other-kid') err = nil, want error")
	}
}

func TestValidateFixedToken(t *testing.T) {
	// Key and Token are examples from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
	compact := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	m, err := createMACwithKID(nil)
	if err != nil {
		t.Fatalf("creating JWTMACwithKID primitive: %v", err)
	}
	opts := &ValidatorOpts{
		ExpectedTypeHeader: refString("JWT"),
		ExpectedIssuer:     refString("joe"),
		FixedNow:           time.Unix(12345, 0),
	}
	pastValidator, err := NewJWTValidator(opts)
	if err != nil {
		t.Fatalf("creating JWTValidator: %v", err)
	}
	// verification succeeds because token was valid valid on January 1, 1970 UTC.
	verifiedJWT, err := m.VerifyMACAndDecodeWithKID(compact, pastValidator, nil)
	if err != nil {
		t.Fatalf("m.VerifyMACAndDecodeWithKID() err = %v, want nil", err)
	}
	typeHeader, err := verifiedJWT.TypeHeader()
	if err != nil {
		t.Errorf("verifiedJWT.TypeHeader() err = %v, want nil", err)
	}
	if typeHeader != *opts.ExpectedTypeHeader {
		t.Errorf("verifiedJWT.TypeHeader() = %q, want %q", typeHeader, *opts.ExpectedTypeHeader)
	}
	issuer, err := verifiedJWT.Issuer()
	if err != nil {
		t.Errorf("verifiedJWT.Issuer() err = %v, want nil", err)
	}
	if issuer != *opts.ExpectedIssuer {
		t.Errorf("verifiedJWT.Issuer() = %q, want %q", issuer, *opts.ExpectedIssuer)
	}
	boolClaim, err := verifiedJWT.BooleanClaim("http://example.com/is_root")
	if err != nil {
		t.Errorf("verifiedJWT.BooleanClaim('http://example.com/is_root') err = %v, want nil", err)
	}
	if boolClaim != true {
		t.Errorf("verifiedJWT.BooleanClaim('http://example.com/is_root') = %q, want true", issuer)
	}

	// expired token fails verification
	opts.FixedNow = time.Now()
	presentValidator, err := NewJWTValidator(opts)
	if err != nil {
		t.Fatalf("creating JWTValidator: %v", err)
	}
	if _, err := m.VerifyMACAndDecodeWithKID(compact, presentValidator, nil); err == nil {
		t.Fatalf("m.VerifyMACAndDecodeWithKID() with expired token err = nil, want error")
	}

	// tampered token verification fails
	tamperedCompact := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXx"
	if _, err := m.VerifyMACAndDecodeWithKID(tamperedCompact, pastValidator, nil); err == nil {
		t.Fatalf("m.VerifyMACAndDecodeWithKID() with expired tampered token err = nil, want error")
	}
}

func TestInvalidTokens(t *testing.T) {
	m, err := createMACwithKID(nil)
	if err != nil {
		t.Fatalf("creating JWTMACwithKID primitive: %v", err)
	}
	validator, err := NewJWTValidator(&ValidatorOpts{})
	if err != nil {
		t.Fatalf("creating JWTValidator: %v", err)
	}
	for _, compact := range []string{
		"eyJhbGciOiJIUzI1NiJ9.e30.abc.",
		"eyJhbGciOiJIUzI1NiJ9?.e30.abc",
		"eyJhbGciOiJIUzI1NiJ9.e30?.abc",
		"eyJhbGciOiJIUzI1NiJ9.e30.abc?",
		"eyJhbGciOiJIUzI1NiJ9.e30",
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOi&Jqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	} {
		if _, err := m.VerifyMACAndDecodeWithKID(compact, validator, nil); err == nil {
			t.Errorf("m.VerifyMACAndDecodeWithKID(%q) err = nil, want error", compact)
		}
	}
}

func TestCustomKIDAndTinkPrefixKeyFail(t *testing.T) {
	m, err := createMACwithKID(refString("custom-kid"))
	if err != nil {
		t.Fatalf("creating JWTMACwithKID primitive: %v", err)
	}
	rawJWT, err := NewRawJWT(&RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	if _, err := m.ComputeMACAndEncodeWithKID(rawJWT, refString("tink-kid")); err == nil {
		t.Errorf("specifying kid when primitive contains kid to ComputeMACAndEncodeWithKID() err = nil, want error")
	}
}
