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
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	jepb "github.com/google/tink/go/proto/jwt_ecdsa_go_proto"
)

const testECDSAVerifierKeyType = "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey"

func TestECDSAVerifierNotImplemented(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	if _, err := km.NewKey(nil); err != errECDSAVerifierNotImplemented {
		t.Fatalf("km.NewKey() err = %v, want %v", err, errECDSAVerifierNotImplemented)
	}
	if _, err := km.NewKeyData(nil); err != errECDSAVerifierNotImplemented {
		t.Fatalf("km.NewKeyData() err = %v, want %v", err, errECDSAVerifierNotImplemented)
	}
}

func TestECDSAVerifierDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	if !km.DoesSupport(testECDSAVerifierKeyType) {
		t.Errorf("km.DoesSupport(%q) = false, want true", testECDSAVerifierKeyType)
	}
	if km.DoesSupport("not.the.actual.key.type") {
		t.Errorf("km.DoesSupport('not.the.actual.key.type') = true, want false")
	}
}

func TestECDSAVerifierTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	if km.TypeURL() != testECDSAVerifierKeyType {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), testECDSAVerifierKeyType)
	}
}

func TestECDSAVerifierPrimitiveWithNilKey(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("km.Primitive(nil) err = nil, want error")
	}
}

func createECDSAPublicKey(algorithm jepb.JwtEcdsaAlgorithm, kid *string, version uint32) (*jepb.JwtEcdsaPublicKey, error) {
	// Public key from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	x, err := base64Decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding x coordinate of public key: %v", err)
	}
	y, err := base64Decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding y coordinate of public key: %v", err)
	}
	var customKID *jepb.JwtEcdsaPublicKey_CustomKid = nil
	if kid != nil {
		customKID = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *kid}
	}
	return &jepb.JwtEcdsaPublicKey{
		Version:   version,
		Algorithm: algorithm,
		X:         x,
		Y:         y,
		CustomKid: customKID,
	}, nil
}

func createECDSASerializedPublicKey(algorithm jepb.JwtEcdsaAlgorithm, kid *string, version uint32) ([]byte, error) {
	pubKey, err := createECDSAPublicKey(algorithm, kid, version)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(pubKey)
}

func TestECDSAVerifierPrimitiveInvalidKeyVersion(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	var invalidKeyVersion uint32 = 1
	serializedPubKey, err := createECDSASerializedPublicKey(jepb.JwtEcdsaAlgorithm_ES384, nil, invalidKeyVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(serializedPubKey); err == nil {
		t.Errorf("km.Primitive() err = nil, want error")
	}
}

func TestECDSAVerifierPrimitiveWithInvalidAlgorithm(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	serializedPubKey, err := createECDSASerializedPublicKey(jepb.JwtEcdsaAlgorithm_ES_UNKNOWN, nil /*=kid*/, 0 /*=version*/)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(serializedPubKey); err == nil {
		t.Errorf("km.Primitive() err = nil, want error")
	}
}

func TestECDSAVerifierPrimitiveVerifyFixedToken(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	serializedPubKey, err := createECDSASerializedPublicKey(jepb.JwtEcdsaAlgorithm_ES256, nil /*=kid*/, 0 /*=version*/)
	if err != nil {
		t.Fatal(err)
	}
	v, err := km.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("km.Primitive() err = %v, want nil", err)
	}
	verifier, ok := v.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive is not a JWT Verifier")
	}
	// compact from https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	compact := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	opts := &ValidatorOpts{
		ExpectedIssuer: refString("joe"),
		FixedNow:       time.Unix(12345, 0),
	}
	validator, err := NewValidator(opts)
	if err != nil {
		t.Fatalf("creating JWTValidator: %v", err)
	}
	// verification succeeds because token was valid valid on January 1, 1970 UTC.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, nil); err != nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = nil) err = %v, want nil", err)
	}
	// verification with KID fails because token contains no KID.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("1234")); err == nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = '1234') err = nil, want error")
	}
}

func TestECDSAVerifierPrimitiveFixedTokenWithKID(t *testing.T) {
	km, err := registry.GetKeyManager(testECDSAVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testECDSAVerifierKeyType, err)
	}
	serializedPubKey, err := createECDSASerializedPublicKey(jepb.JwtEcdsaAlgorithm_ES256, refString("1234"), 0 /*=version*/)
	if err != nil {
		t.Fatal(err)
	}
	v, err := km.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("km.Primitive() err = %v, want nil", err)
	}
	verifier, ok := v.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive is not a JWT Verifier")
	}
	// compact is the claim set '{}' with header '{"alg":"ES256", "kid":"1234"}'
	// signed with private key as specified in https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	compact := "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQifQ.e30.3jdIhPC4qfXrzE8ds6tyrLoqqmwfXX-CyfP9YG0k_LFeuF5wYPsmgPeUthMFfvPIN63zQ9i-I5BQLJVwaRTTdw"
	validator, err := NewValidator(&ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("creating JWTValidator: %v", err)
	}
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, nil); err != nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = nil) err = %v, want nil ", err)
	}
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("1234")); err == nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = 1234) err = nil, want error ")
	}
}
