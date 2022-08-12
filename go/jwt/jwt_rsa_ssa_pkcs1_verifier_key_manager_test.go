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
	jrsppb "github.com/google/tink/go/proto/jwt_rsa_ssa_pkcs1_go_proto"
)

const testJWTRSVerifierKeyType = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"

func makeValidRSPublicKey() (*jrsppb.JwtRsaSsaPkcs1PublicKey, error) {
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
	return &jrsppb.JwtRsaSsaPkcs1PublicKey{
		Algorithm: jrsppb.JwtRsaSsaPkcs1Algorithm_RS256,
		Version:   0,
		N:         n,
		E:         e,
		CustomKid: nil,
	}, nil
}

func TestJWTRSVerifierNotImplemented(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtRSVerifierKeyManager{}
	keyFormat := &jrsppb.JwtRsaSsaPkcs1KeyFormat{
		Version:           0,
		Algorithm:         jrsppb.JwtRsaSsaPkcs1Algorithm_RS256,
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

func TestJWTRSVerifierDoesSupport(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtRSVerifierKeyManager{}
	if !km.DoesSupport(testJWTRSVerifierKeyType) {
		t.Errorf("DoesSupport(%q) = false, want true", testJWTRSVerifierKeyType)
	}
	if km.DoesSupport("not.the.actual.key.type") {
		t.Errorf("km.DoesSupport('not.the.actual.key.type') = true, want false")
	}
}

func TestJWTRSVerifierTypeURL(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtRSVerifierKeyManager{}
	if km.TypeURL() != testJWTRSVerifierKeyType {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), testJWTRSVerifierKeyType)
	}
}

func TestJWTRSVerifierPrimitiveWithInvalidKey(t *testing.T) {
	type testCase struct {
		name   string
		pubKey *jrsppb.JwtRsaSsaPkcs1PublicKey
	}
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtRSVerifierKeyManager{}
	validPubKey, err := makeValidRSPublicKey()
	if err != nil {
		t.Fatalf("makeValidRSAPSSPKCS1PrivKey() err = %v, want nil", err)
	}
	for _, tc := range []testCase{
		{
			name:   "nil public key",
			pubKey: nil,
		},
		{
			name:   "empty public key",
			pubKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{},
		},
		{
			name: "invalid version",
			pubKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
				Version:   validPubKey.Version + 1,
				Algorithm: validPubKey.GetAlgorithm(),
				N:         validPubKey.GetN(),
				E:         validPubKey.GetE(),
				CustomKid: validPubKey.GetCustomKid(),
			},
		},
		{
			name: "invalid algorithm",
			pubKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
				Algorithm: jrsppb.JwtRsaSsaPkcs1Algorithm_RS_UNKNOWN,
				Version:   validPubKey.Version,
				N:         validPubKey.GetN(),
				E:         validPubKey.GetE(),
				CustomKid: validPubKey.GetCustomKid(),
			},
		},
		{
			name: "invalid modulus",
			pubKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
				Version:   validPubKey.Version,
				Algorithm: validPubKey.GetAlgorithm(),
				N:         []byte{0x00},
				E:         validPubKey.GetE(),
				CustomKid: validPubKey.GetCustomKid(),
			},
		},
		{
			name: "invalid exponent",
			pubKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
				Version:   validPubKey.Version,
				Algorithm: validPubKey.GetAlgorithm(),
				N:         validPubKey.GetN(),
				E:         []byte{0x05, 0x04, 0x03},
				CustomKid: validPubKey.GetCustomKid(),
			},
		},
		{
			name: "exponent larger than 64 bits",
			pubKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
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

func TestJWTRSVerifierPrimitiveWithInvalidSerializedKey(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtRSVerifierKeyManager{}
	if _, err := km.Primitive([]byte("invalid_serialization")); err == nil {
		t.Errorf("Primitive() err = nil, want error")
	}
}

func TestJWTRSVerifierPrimitiveVerifyFixedToken(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtRSVerifierKeyManager{}
	pubKey, err := makeValidRSPublicKey()
	if err != nil {
		t.Fatalf("makeValidRSPublicKey() err = %v, want nil", err)
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
	// compact from https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
	compact := "eyJhbGciOiJSUzI1NiJ9" +
		"." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
		"AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
		"BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
		"0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
		"hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
		"p0igcN_IoypGlUPQGe77Rw"
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
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("1234")); err == nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = '1234') err = nil, want error")
	}
}

func TestJWTRSVerifierPrimitiveWithCustomKID(t *testing.T) {
	km := &jwtRSVerifierKeyManager{}
	pubKey, err := makeValidRSPublicKey()
	if err != nil {
		t.Fatalf("makeValidRSPublicKey() err = %v, want nil", err)
	}
	pubKey.CustomKid = &jrsppb.JwtRsaSsaPkcs1PublicKey_CustomKid{
		Value: "8542",
	}
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	v, err := km.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("km.Primitive() err = %v, want nil", err)
	}
	// similar to https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2 but with KID 8542
	compact := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg1NDIifQ" +
		"." +
		"eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290I" +
		"jp0cnVlLCJpc3MiOiJqb2UifQ" +
		"." +
		"aoQ4f8U_gpIymZM20rbAG2kjw5H5EKruPqPWf_wsEDeKPSjCXzkW016s5UqTz" +
		"dJ72ZEP05PPZHs4VtZslUXQajLlZNgbK3UJ86QYBrqENq0Pwnhh43TVPi9lrF" +
		"xOLjSQHAqKXYCy4aflqRdZqP9QqpLqaKtB1mAcDNM25Qx01Ix9FV_ngqI5OLD" +
		"OYyDp5HoxgMAV-jNR9yq-r31_EBQmmDFHC8K8NJ5XLa4SybbhNlUWi6b1p7sQ" +
		"NIOcb6RtSGSL73m-FYOo_dOMZ1ZNd7a_JiJe7QZ3-v1Dnw9GBSxvLdtKye2Fu" +
		"ZHietYMJJczj14KeDbBK6TwmbUM8AacLt-JGg"
	verifier, ok := v.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT Verifier")
	}
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
	// verification with custom KID and Tink KID fails, there can only be one KID set.
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("8542")); err == nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = '8542') err = nil, want error")
	}

	pubKey.CustomKid = &jrsppb.JwtRsaSsaPkcs1PublicKey_CustomKid{
		Value: "1234",
	}
	serializedPubKey, err = proto.Marshal(pubKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	v, err = km.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("km.Primitive() err = %v, want nil", err)
	}
	verifierWrongKID, ok := v.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT Verifier")
	}
	// primitive contains invalid Custom KID which fails verification.
	if _, err := verifierWrongKID.VerifyAndDecodeWithKID(compact, validator, nil); err == nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = nil) err = nil, want error")
	}
}

func TestJWTRSVerifierPrimitiveWithTinkKID(t *testing.T) {
	// TODO(b/173082704): call registry to get key manager once added to cross language tests.
	km := &jwtRSVerifierKeyManager{}
	pubKey, err := makeValidRSPublicKey()
	if err != nil {
		t.Fatalf("makeValidRSPublicKey() err = %v, want nil", err)
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
	// similar to https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2 but with KID 8542
	compact := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg1NDIifQ" +
		"." +
		"eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290I" +
		"jp0cnVlLCJpc3MiOiJqb2UifQ" +
		"." +
		"aoQ4f8U_gpIymZM20rbAG2kjw5H5EKruPqPWf_wsEDeKPSjCXzkW016s5UqTz" +
		"dJ72ZEP05PPZHs4VtZslUXQajLlZNgbK3UJ86QYBrqENq0Pwnhh43TVPi9lrF" +
		"xOLjSQHAqKXYCy4aflqRdZqP9QqpLqaKtB1mAcDNM25Qx01Ix9FV_ngqI5OLD" +
		"OYyDp5HoxgMAV-jNR9yq-r31_EBQmmDFHC8K8NJ5XLa4SybbhNlUWi6b1p7sQ" +
		"NIOcb6RtSGSL73m-FYOo_dOMZ1ZNd7a_JiJe7QZ3-v1Dnw9GBSxvLdtKye2Fu" +
		"ZHietYMJJczj14KeDbBK6TwmbUM8AacLt-JGg"
	issuer := "joe"
	validator, err := NewValidator(&ValidatorOpts{
		ExpectedIssuer: &issuer,
		FixedNow:       time.Unix(123, 0),
	})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("8542")); err != nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = '8542') err = %v, want nil", err)
	}
	// verification fails with invalid KID
	if _, err := verifier.VerifyAndDecodeWithKID(compact, validator, refString("2333")); err == nil {
		t.Errorf("verifier.VerifyAndDecodeWithKID(kid = '2333') err = nil, want error")
	}
}
