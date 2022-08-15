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
	"github.com/google/tink/go/subtle/random"
	jrsppb "github.com/google/tink/go/proto/jwt_rsa_ssa_pss_go_proto"
)

const testJWTPSVerifierKeyType = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey"

func makeValidPSPublicKey() (*jrsppb.JwtRsaSsaPssPublicKey, error) {
	// Public key taken from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
	n, err := base64Decode(
		"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
			"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
			"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
			"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
			"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
			"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding modulus: %v", err)
	}
	e, err := base64Decode("AQAB")
	if err != nil {
		return nil, fmt.Errorf("base64 decoding public exponent: %v", err)
	}
	return &jrsppb.JwtRsaSsaPssPublicKey{
		Algorithm: jrsppb.JwtRsaSsaPssAlgorithm_PS256,
		Version:   0,
		N:         n,
		E:         e,
		CustomKid: nil,
	}, nil
}

func TestJWTPSVerifierNotImplemented(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtPSVerifierKeyManager{}
	keyFormat := &jrsppb.JwtRsaSsaPssKeyFormat{
		Version:           0,
		Algorithm:         jrsppb.JwtRsaSsaPssAlgorithm_PS256,
		ModulusSizeInBits: 3072,
		PublicExponent:    []byte{0x01, 0x00, 0x01}, // 65537 aka F4
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	if _, err := km.NewKey(serializedKeyFormat); err == nil {
		t.Fatalf("km.NewKey() err = nil, want error")
	}
	if _, err := km.NewKeyData(serializedKeyFormat); err == nil {
		t.Fatalf("km.NewKeyData() err = nil, want error")
	}
}

func TestJWTPSVerifierDoesSupport(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtPSVerifierKeyManager{}
	if !km.DoesSupport(testJWTPSVerifierKeyType) {
		t.Errorf("DoesSupport(%q) = false, want true", testJWTPSVerifierKeyType)
	}
	if km.DoesSupport("not.the.actual.key.type") {
		t.Errorf("km.DoesSupport('not.the.actual.key.type') = true, want false")
	}
}

func TestJWTPSVerifierTypeURL(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtPSVerifierKeyManager{}
	if km.TypeURL() != testJWTPSVerifierKeyType {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), testJWTPSVerifierKeyType)
	}
}

func TestJWTPSVerifierPrimitiveWithInvalidKey(t *testing.T) {
	type testCase struct {
		name   string
		pubKey *jrsppb.JwtRsaSsaPssPublicKey
	}
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtPSVerifierKeyManager{}
	validPubKey, err := makeValidPSPublicKey()
	if err != nil {
		t.Fatalf("makeValidPSPublicKey() err = %v, want nil", err)
	}
	for _, tc := range []testCase{
		{
			name:   "nil public key",
			pubKey: nil,
		},
		{
			name:   "empty public key",
			pubKey: &jrsppb.JwtRsaSsaPssPublicKey{},
		},
		{
			name: "invalid version",
			pubKey: &jrsppb.JwtRsaSsaPssPublicKey{
				Version:   validPubKey.Version + 1,
				Algorithm: validPubKey.GetAlgorithm(),
				N:         validPubKey.GetN(),
				E:         validPubKey.GetE(),
				CustomKid: validPubKey.GetCustomKid(),
			},
		},
		{
			name: "invalid algorithm",
			pubKey: &jrsppb.JwtRsaSsaPssPublicKey{
				Algorithm: jrsppb.JwtRsaSsaPssAlgorithm_PS_UNKNOWN,
				Version:   validPubKey.Version,
				N:         validPubKey.GetN(),
				E:         validPubKey.GetE(),
				CustomKid: validPubKey.GetCustomKid(),
			},
		},
		{
			name: "invalid modulus",
			pubKey: &jrsppb.JwtRsaSsaPssPublicKey{
				Version:   validPubKey.Version,
				Algorithm: validPubKey.GetAlgorithm(),
				N:         []byte{0x00},
				E:         validPubKey.GetE(),
				CustomKid: validPubKey.GetCustomKid(),
			},
		},
		{
			name: "invalid exponent",
			pubKey: &jrsppb.JwtRsaSsaPssPublicKey{
				Version:   validPubKey.Version,
				Algorithm: validPubKey.GetAlgorithm(),
				N:         validPubKey.GetN(),
				E:         []byte{0x05, 0x04, 0x03},
				CustomKid: validPubKey.GetCustomKid(),
			},
		},
		{
			name: "exponent larger than 64 bits",
			pubKey: &jrsppb.JwtRsaSsaPssPublicKey{
				Version:   validPubKey.Version,
				Algorithm: validPubKey.GetAlgorithm(),
				N:         validPubKey.GetN(),
				E:         random.GetRandomBytes(65),
				CustomKid: validPubKey.GetCustomKid(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedPubKey, err := proto.Marshal(tc.pubKey)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := km.Primitive(serializedPubKey); err == nil {
				t.Errorf("Primitive() err = nil, want error")
			}
		})
	}
}

func TestJWTPSVerifierPrimitiveVerifyFixedToken(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtPSVerifierKeyManager{}
	pubKey, err := makeValidPSPublicKey()
	if err != nil {
		t.Fatalf("makeValidPSPublicKey() err = %v, want nil", err)
	}
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	v, err := km.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("km.Primitive() err = %v, want nil", err)
	}
	verifier, ok := v.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT Verifier")
	}
	// // similar to https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
	compact := "eyJhbGciOiJQUzI1NiJ9" +
		"." +
		"eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ" +
		"." +
		"PpLcmEZ2zlsOmYygy8SU9Zxwab9deDuibgCg8dCZ8Po1N51kyMU9Mty7wj9fTCOONNqu3QxLe_2Wu_BkVhz41W" +
		"bxXrP3cci7deSnQmgN2ZkA23egSFfMoDd56CFvY3-eaG22NRxPsDWypECdDgXJXoSPnlRxgtaJDxUUD3Ej9DZ4" +
		"gmdVcG4ZqmLSxoIAXtmjGi-Da_fqf48DOKaL5AI1uE2SW_byXPXdtaD_oIvNoeL0J5wuU2cSJQutu-UCyfO1rl" +
		"R3DTOzR_XRx7dEzziqfzP7_YlSxdidkph1Jrh1DIapxsWrnaShYFofS35Vg17SdciALeRMnQHwhClJJqgChg"
	issuer := "joe"
	validator, err := NewValidator(&ValidatorOpts{
		ExpectedIssuer: &issuer,
		FixedNow:       time.Unix(123, 0),
	})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	// verification succeeds because token was valid on January 1, 1970 UTC.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, nil); err != nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = nil) err = %v, want nil", err)
	}
	// verification with KID fails because token contains no KID.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("")); err == nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = '1234') err = nil, want error")
	}
}

func TestJWTPSVerifierPrimitiveVerifyFixedTokenWithCustomKID(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtPSVerifierKeyManager{}
	pubKey, err := makeValidPSPublicKey()
	if err != nil {
		t.Fatalf("makeValidPSPublicKey() err = %v, want nil", err)
	}
	pubKey.CustomKid = &jrsppb.JwtRsaSsaPssPublicKey_CustomKid{
		Value: "oneoh",
	}
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	v, err := km.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("km.Primitive() err = %v, want nil", err)
	}
	verifier, ok := v.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT Verifier")
	}
	// // similar to https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2 but with KID "oneoh"
	compact := "eyJhbGciOiJQUzI1NiIsImtpZCI6Im9uZW9oIn0" +
		"." +
		"eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ" +
		"." +
		"hrkeS71m1bg9tDBfEI3P-E6CkLZuNOguG0LlY5Yb-HzjFan9_LmvmemMCYYTsifNJkJkiSZRwkv7BQ0Svd6Rn_" +
		"TzckQdpr37pez_2mywfpAbYWxi40n35q9Q3W8IWgbpZFIRIru0n1R7v4XIpkVbd90IwahgZG3Yhvlwt3-EWCwz" +
		"7tb3_EbcFFHsSK0PH-b9mPwrUzb_l-jJR5T2zATc3lTriyGsOhyubBAwcxKuAEg5Ru7_vgLI352jEzjFsz05Fu" +
		"QVMEtdBGqiLn2iIu8yDQtKMPm-FBhBO_uomHcxjLY4nBziAkba3WPUGkB4HvbIGQz9ZedUjd2ivCQ52GT2uw"
	issuer := "joe"
	validator, err := NewValidator(&ValidatorOpts{
		ExpectedIssuer: &issuer,
		FixedNow:       time.Unix(123, 0),
	})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	// verification succeeds because token was valid on January 1, 1970 UTC.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, nil); err != nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = 'oneoh') err = %v, want nil", err)
	}
	// verification fails with Custom KID and Tink KID, only one can be present.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("oneoh")); err == nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = '1234') err = nil, want error")
	}
}

func TestJWTPSVerifierPrimitiveVerifyFixedTokenWithTinkKID(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtPSVerifierKeyManager{}
	pubKey, err := makeValidPSPublicKey()
	if err != nil {
		t.Fatalf("makeValidPSPublicKey() err = %v, want nil", err)
	}
	pubKey.CustomKid = nil
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	v, err := km.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("km.Primitive() err = %v, want nil", err)
	}
	verifier, ok := v.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT Verifier")
	}
	// // similar to https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2 but with KID "oneoh"
	compact := "eyJhbGciOiJQUzI1NiIsImtpZCI6Im9uZW9oIn0" +
		"." +
		"eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ" +
		"." +
		"hrkeS71m1bg9tDBfEI3P-E6CkLZuNOguG0LlY5Yb-HzjFan9_LmvmemMCYYTsifNJkJkiSZRwkv7BQ0Svd6Rn_" +
		"TzckQdpr37pez_2mywfpAbYWxi40n35q9Q3W8IWgbpZFIRIru0n1R7v4XIpkVbd90IwahgZG3Yhvlwt3-EWCwz" +
		"7tb3_EbcFFHsSK0PH-b9mPwrUzb_l-jJR5T2zATc3lTriyGsOhyubBAwcxKuAEg5Ru7_vgLI352jEzjFsz05Fu" +
		"QVMEtdBGqiLn2iIu8yDQtKMPm-FBhBO_uomHcxjLY4nBziAkba3WPUGkB4HvbIGQz9ZedUjd2ivCQ52GT2uw"
	issuer := "joe"
	validator, err := NewValidator(&ValidatorOpts{
		ExpectedIssuer: &issuer,
		FixedNow:       time.Unix(123, 0),
	})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	// verification succeeds because token was valid on January 1, 1970 UTC.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("oneoh")); err != nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = 'oneoh') err = %v, want nil", err)
	}
	// verification without Tink KID ignores KID header.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, nil); err != nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = nil) err = %v, want nil", err)
	}
	// verification with incorrect KID fails because token contains KID header.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("1234")); err == nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = '1234') err = nil, want error")
	}
}
