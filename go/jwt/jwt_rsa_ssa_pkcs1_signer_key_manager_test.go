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
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/google/tink/go/core/registry"
	jrsppb "github.com/google/tink/go/proto/jwt_rsa_ssa_pkcs1_go_proto"
	tpb "github.com/google/tink/go/proto/tink_go_proto"
)

const testJWTRSSignerKeyType = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey"

func makeValidJWTRSPrivateKey() (*jrsppb.JwtRsaSsaPkcs1PrivateKey, error) {
	// key taken from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
	pubKey, err := makeValidRSPublicKey()
	if err != nil {
		return nil, err
	}
	d, err := base64Decode(
		"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
			"jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
			"BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
			"439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
			"CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
			"BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ")
	if err != nil {
		return nil, err
	}
	p, err := base64Decode(
		"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
			"YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
			"BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc")
	if err != nil {
		return nil, err
	}
	q, err := base64Decode(
		"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
			"ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
			"-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc")
	if err != nil {
		return nil, err
	}
	dp, err := base64Decode(
		"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
			"CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
			"34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0")
	if err != nil {
		return nil, err
	}
	dq, err := base64Decode(
		"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
			"7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
			"NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU")
	if err != nil {
		return nil, err
	}
	qi, err := base64Decode(
		"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
			"y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
			"W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U")
	if err != nil {
		return nil, err
	}
	return &jrsppb.JwtRsaSsaPkcs1PrivateKey{
		PublicKey: pubKey,
		Version:   0,
		D:         d,
		P:         p,
		Q:         q,
		Dp:        dp,
		Dq:        dq,
		Crt:       qi,
	}, nil
}

func TestJWTRSSignerKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	if !km.DoesSupport(testJWTRSSignerKeyType) {
		t.Errorf("DoesSupport(%q) = false, want true", testJWTRSSignerKeyType)
	}
	if km.DoesSupport("invalid.key.type") {
		t.Errorf("DoesSupport(%q) = true, want false", "invalid.key.type")
	}
}

func TestJWTRSSignerKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	if km.TypeURL() != testJWTRSSignerKeyType {
		t.Errorf("TypeURL() = %v, want = %v", km.TypeURL(), testJWTRSSignerKeyType)
	}
}

func TestJWTRSSignerKeyManagerPrimitiveSignAndVerify(t *testing.T) {
	skm, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	privKey, err := makeValidJWTRSPrivateKey()
	if err != nil {
		t.Fatalf("makeValidJWTRSPrivateKey() err = %v, want nil", err)
	}
	privKey.PublicKey.CustomKid = nil
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	sp, err := skm.Primitive(serializedPrivKey)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	signer, ok := sp.(*signerWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT signer")
	}
	unsigned, err := NewRawJWT(&RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	signed, err := signer.SignAndEncodeWithKID(unsigned, nil)
	if err != nil {
		t.Fatalf("SignAndEncodeWithKID(kid = nil) err = %v, want nil", err)
	}
	vkm, err := registry.GetKeyManager(testJWTRSVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSVerifierKeyType, err)
	}
	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	vp, err := vkm.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	verifier, ok := vp.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT Verifier")
	}
	validator, err := NewValidator(&ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecodeWithKID(signed, validator, nil); err != nil {
		t.Errorf("VerifyAndDecodeWithKID(kid = nil) err = %v, want nil", err)
	}
	// Shouldn't contain KID header at all.
	if _, err := verifier.VerifyAndDecodeWithKID(signed, validator, refString("")); err == nil {
		t.Errorf("VerifyAndDecodeWithKID(kid = '123') err = nil, want error")
	}
}

func TestJWTRSSignerKeyManagerPrimitiveWithInvalidSerializedKeyFails(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	if _, err := km.Primitive([]byte("invalid_serialization")); err == nil {
		t.Fatalf("Primitive() err = nil, want error")
	}
}

func TestJWTRSSignerKeyManagerPrimitiveSignAndVerifyWithTinkKID(t *testing.T) {
	skm, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	privKey, err := makeValidJWTRSPrivateKey()
	if err != nil {
		t.Fatalf("makeValidJWTRSPrivateKey() err = %v, want nil", err)
	}
	privKey.PublicKey.CustomKid = nil
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	sp, err := skm.Primitive(serializedPrivKey)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	signer, ok := sp.(*signerWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT signer")
	}
	unsigned, err := NewRawJWT(&RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	signedWithKID, err := signer.SignAndEncodeWithKID(unsigned, refString("555"))
	if err != nil {
		t.Fatalf("SignAndEncodeWithKID(kid = '555') err = %v, want nil", err)
	}
	vkm, err := registry.GetKeyManager(testJWTRSVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSVerifierKeyType, err)
	}
	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	vp, err := vkm.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	verifier, ok := vp.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT Verifier")
	}
	validator, err := NewValidator(&ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecodeWithKID(signedWithKID, validator, refString("555")); err != nil {
		t.Fatalf("VerifyAndDecodeWithKID(kid = '555') err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecodeWithKID(signedWithKID, validator, refString("0")); err == nil {
		t.Fatalf("VerifyAndDecodeWithKID(kid = '0') err = nil, want error")
	}
}

func TestJWTRSSignerKeyManagerPrimitiveSignAndVerifyWithCustomKID(t *testing.T) {
	skm, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	privKey, err := makeValidJWTRSPrivateKey()
	if err != nil {
		t.Fatalf("makeValidJWTRSPrivateKey() err = %v, want nil", err)
	}
	privKey.PublicKey.CustomKid = &jrsppb.JwtRsaSsaPkcs1PublicKey_CustomKid{
		Value: "7843",
	}
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	sp, err := skm.Primitive(serializedPrivKey)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	signer, ok := sp.(*signerWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT signer")
	}
	unsigned, err := NewRawJWT(&RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	signed, err := signer.SignAndEncodeWithKID(unsigned, nil)
	if err != nil {
		t.Fatalf("SignAndEncodeWithKID(kid = nil) err = %v, want nil", err)
	}
	if _, err := signer.SignAndEncodeWithKID(unsigned, refString("555")); err == nil {
		t.Fatalf("SignAndEncodeWithKID(kid = '555') err = nil, want error")
	}
	vkm, err := registry.GetKeyManager(testJWTRSVerifierKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSVerifierKeyType, err)
	}
	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	vp, err := vkm.Primitive(serializedPubKey)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	verifier, ok := vp.(*verifierWithKID)
	if !ok {
		t.Fatalf("primitive isn't a JWT Verifier")
	}
	validator, err := NewValidator(&ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecodeWithKID(signed, validator, nil); err != nil {
		t.Fatalf("VerifyAndDecodeWithKID(kid = nil) err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecodeWithKID(signed, validator, refString("7843")); err == nil {
		t.Fatalf("VerifyAndDecodeWithKID(kid = '7843') err = nil, want error")
	}
}

func TestJWTRSSignerKeyManagerPrimitiveFailsWithInvalidKey(t *testing.T) {
	type testCase struct {
		name    string
		privKey *jrsppb.JwtRsaSsaPkcs1PrivateKey
	}
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	validPrivKey, err := makeValidJWTRSPrivateKey()
	if err != nil {
		t.Fatalf("makeValidJWTRSPrivateKey() err = %v, want nil", err)
	}
	for _, tc := range []testCase{
		{
			name:    "nil private key",
			privKey: nil,
		},
		{
			name:    "empty private key",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{},
		},
		{
			name: "invalid private key version",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: validPrivKey.GetPublicKey(),
				Version:   validPrivKey.GetVersion() + 1,
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid D private key value",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: validPrivKey.GetPublicKey(),
				Version:   validPrivKey.GetVersion(),
				D:         nil,
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid P private key value",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: validPrivKey.GetPublicKey(),
				Version:   validPrivKey.GetVersion(),
				D:         validPrivKey.GetD(),
				P:         nil,
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid Q private key value",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: validPrivKey.GetPublicKey(),
				Version:   validPrivKey.GetVersion(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         nil,
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid pre computed Dp key value",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: validPrivKey.GetPublicKey(),
				Version:   validPrivKey.GetVersion(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        nil,
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid pre computed Dq key value",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: validPrivKey.GetPublicKey(),
				Version:   validPrivKey.GetVersion(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        nil,
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid pre computed Dq key value",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: validPrivKey.GetPublicKey(),
				Version:   validPrivKey.GetVersion(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       nil,
			},
		},
		{
			name: "nil public key",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: nil,
				Version:   validPrivKey.GetVersion(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "empty public key",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{},
				Version:   validPrivKey.GetVersion(),
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid private key version",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: validPrivKey.GetPublicKey(),
				Version:   validPrivKey.Version + 1,
				D:         validPrivKey.GetD(),
				P:         validPrivKey.GetP(),
				Q:         validPrivKey.GetQ(),
				Dp:        validPrivKey.GetDp(),
				Dq:        validPrivKey.GetDq(),
				Crt:       validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid public key version",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
					Version:   validPrivKey.GetPublicKey().GetVersion() + 1,
					Algorithm: validPrivKey.GetPublicKey().GetAlgorithm(),
					N:         validPrivKey.GetPublicKey().GetN(),
					E:         validPrivKey.GetPublicKey().GetE(),
					CustomKid: validPrivKey.GetPublicKey().GetCustomKid(),
				},
				Version: validPrivKey.GetVersion(),
				D:       validPrivKey.GetD(),
				P:       validPrivKey.GetP(),
				Q:       validPrivKey.GetQ(),
				Dp:      validPrivKey.GetDp(),
				Dq:      validPrivKey.GetDq(),
				Crt:     validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid algorithm",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
					Version:   validPrivKey.GetPublicKey().GetVersion(),
					Algorithm: jrsppb.JwtRsaSsaPkcs1Algorithm_RS_UNKNOWN,
					N:         validPrivKey.GetPublicKey().GetN(),
					E:         validPrivKey.GetPublicKey().GetE(),
					CustomKid: validPrivKey.GetPublicKey().GetCustomKid(),
				},
				Version: validPrivKey.GetVersion(),
				D:       validPrivKey.GetD(),
				P:       validPrivKey.GetP(),
				Q:       validPrivKey.GetQ(),
				Dp:      validPrivKey.GetDp(),
				Dq:      validPrivKey.GetDq(),
				Crt:     validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid modulus",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
					Version:   validPrivKey.GetPublicKey().GetVersion(),
					Algorithm: validPrivKey.GetPublicKey().GetAlgorithm(),
					N:         []byte{0x00, 0x01},
					E:         validPrivKey.GetPublicKey().GetE(),
					CustomKid: validPrivKey.GetPublicKey().GetCustomKid(),
				},
				Version: validPrivKey.GetVersion(),
				D:       validPrivKey.GetD(),
				P:       validPrivKey.GetP(),
				Q:       validPrivKey.GetQ(),
				Dp:      validPrivKey.GetDp(),
				Dq:      validPrivKey.GetDq(),
				Crt:     validPrivKey.GetCrt(),
			},
		},
		{
			name: "invalid exponent",
			privKey: &jrsppb.JwtRsaSsaPkcs1PrivateKey{
				PublicKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
					Version:   validPrivKey.GetPublicKey().GetVersion(),
					Algorithm: validPrivKey.GetPublicKey().GetAlgorithm(),
					N:         validPrivKey.GetPublicKey().GetN(),
					E:         []byte{0x07},
					CustomKid: validPrivKey.GetPublicKey().GetCustomKid(),
				},
				Version: validPrivKey.GetVersion(),
				D:       validPrivKey.GetD(),
				P:       validPrivKey.GetP(),
				Q:       validPrivKey.GetQ(),
				Dp:      validPrivKey.GetDp(),
				Dq:      validPrivKey.GetDq(),
				Crt:     validPrivKey.GetCrt(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedPrivKey, err := proto.Marshal(tc.privKey)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := km.Primitive(serializedPrivKey); err == nil {
				t.Fatalf("Primitive() err = nil, want error")
			}
			if _, err := km.(registry.PrivateKeyManager).PublicKeyData(serializedPrivKey); err == nil {
				t.Fatalf("PublicKeyData() err = nil, want error")
			}
		})
	}
}

func TestJWTRSSignerKeyManagerPublicKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	privKey, err := makeValidJWTRSPrivateKey()
	if err != nil {
		t.Fatalf("makeValidJWTRSPrivateKey() err = %v, want nil", err)
	}
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	pubKeyData, err := km.(registry.PrivateKeyManager).PublicKeyData(serializedPrivKey)
	if err != nil {
		t.Fatalf("PublicKeyData() err = %v, want nil", err)
	}
	if pubKeyData.GetKeyMaterialType() != tpb.KeyData_ASYMMETRIC_PUBLIC {
		t.Errorf("GetKeyMaterialType() = %v, want %v", pubKeyData.GetKeyMaterialType(), tpb.KeyData_ASYMMETRIC_PUBLIC)
	}
	if pubKeyData.GetTypeUrl() != testJWTRSVerifierKeyType {
		t.Errorf("TypeURL() = %v, want %v", pubKeyData.GetTypeUrl(), testJWTRSVerifierKeyType)
	}
	gotPubKey := &jrsppb.JwtRsaSsaPkcs1PublicKey{}
	if err := proto.Unmarshal(pubKeyData.GetValue(), gotPubKey); err != nil {
		t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
	}
	if !cmp.Equal(gotPubKey, privKey.GetPublicKey(), protocmp.Transform()) {
		t.Errorf("got = %v, want = %v", gotPubKey, privKey.GetPublicKey())
	}
}

func TestJWTRSSignerKeyManagerPublicKeyDataWithNilKeyFails(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	if _, err := km.(registry.PrivateKeyManager).PublicKeyData(nil); err == nil {
		t.Fatalf("PublicKeyData(nil) err = nil, want error")
	}
}

func TestJWTRSSignerKeyManagerNewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	type testCase struct {
		name      string
		keyFormat *jrsppb.JwtRsaSsaPkcs1KeyFormat
	}
	for _, tc := range []testCase{
		{
			name: "RS256 with 3072 modulus",
			keyFormat: &jrsppb.JwtRsaSsaPkcs1KeyFormat{
				Version:           0,
				Algorithm:         jrsppb.JwtRsaSsaPkcs1Algorithm_RS256,
				ModulusSizeInBits: 3072,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
			},
		},
		{
			name: "RS384 with 3072 modulus",
			keyFormat: &jrsppb.JwtRsaSsaPkcs1KeyFormat{
				Version:           0,
				Algorithm:         jrsppb.JwtRsaSsaPkcs1Algorithm_RS384,
				ModulusSizeInBits: 3072,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
			},
		},
		{
			name: "RS512 with 4096 modulus",
			keyFormat: &jrsppb.JwtRsaSsaPkcs1KeyFormat{
				Version:           0,
				Algorithm:         jrsppb.JwtRsaSsaPkcs1Algorithm_RS512,
				ModulusSizeInBits: 4096,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			keyData, err := km.NewKeyData(serializedKeyFormat)
			if err != nil {
				t.Fatalf("NewKeyData() err = %v, want nil", err)
			}
			if keyData.GetTypeUrl() != testJWTRSSignerKeyType {
				t.Errorf("GetTypeURL() = %v, want %v", keyData.GetTypeUrl(), testJWTRSSignerKeyType)
			}
			if keyData.GetKeyMaterialType() != tpb.KeyData_ASYMMETRIC_PRIVATE {
				t.Errorf("GetKeyMaterialType() = %v, want %v", keyData.GetKeyMaterialType(), tpb.KeyData_ASYMMETRIC_PRIVATE)
			}
			key := &jrsppb.JwtRsaSsaPkcs1PrivateKey{}
			if err := proto.Unmarshal(keyData.GetValue(), key); err != nil {
				t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
			}
			pubKey := key.GetPublicKey()
			got, want := pubKey.GetAlgorithm(), tc.keyFormat.GetAlgorithm()
			if got != want {
				t.Errorf("GetAlgorithm() = %v, want %v", got, want)
			}
			gotE, wantE := pubKey.GetE(), tc.keyFormat.GetPublicExponent()
			if !cmp.Equal(gotE, wantE) {
				t.Errorf("Exponent = %v, want %v", gotE, wantE)
			}
			gotMod := new(big.Int).SetBytes(pubKey.GetN()).BitLen()
			wantMod := int(tc.keyFormat.GetModulusSizeInBits())
			if gotMod != wantMod {
				t.Errorf("Modulus Size in Bits = %d, want %d", gotMod, wantMod)
			}
		})
	}
}

func TestJWTRSSignerKeyManagerNewKeyDataFailsWithInvalidFormat(t *testing.T) {
	type testCase struct {
		name      string
		keyFormat *jrsppb.JwtRsaSsaPkcs1KeyFormat
	}
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	for _, tc := range []testCase{
		{
			name:      "nil key format",
			keyFormat: nil,
		},
		{
			name:      "empty key format",
			keyFormat: &jrsppb.JwtRsaSsaPkcs1KeyFormat{},
		},
		{
			name: "invalid version",
			keyFormat: &jrsppb.JwtRsaSsaPkcs1KeyFormat{
				Algorithm:         jrsppb.JwtRsaSsaPkcs1Algorithm_RS256,
				Version:           1,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
				ModulusSizeInBits: 3072,
			},
		},
		{
			name: "invalid algorithm",
			keyFormat: &jrsppb.JwtRsaSsaPkcs1KeyFormat{
				Algorithm:         jrsppb.JwtRsaSsaPkcs1Algorithm_RS_UNKNOWN,
				Version:           0,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
				ModulusSizeInBits: 3072,
			},
		},
		{
			name: "invalid public exponent",
			keyFormat: &jrsppb.JwtRsaSsaPkcs1KeyFormat{
				Algorithm:         jrsppb.JwtRsaSsaPkcs1Algorithm_RS256,
				Version:           0,
				PublicExponent:    []byte{0x01},
				ModulusSizeInBits: 3072,
			},
		},
		{
			name: "invalid modulus size",
			keyFormat: &jrsppb.JwtRsaSsaPkcs1KeyFormat{
				Algorithm:         jrsppb.JwtRsaSsaPkcs1Algorithm_RS256,
				Version:           0,
				PublicExponent:    []byte{0x01, 0x00, 0x01},
				ModulusSizeInBits: 1024,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := km.NewKeyData(serializedKeyFormat); err == nil {
				t.Fatalf("NewKeyData() err = nil, want error")
			}
			if _, err := km.NewKey(serializedKeyFormat); err == nil {
				t.Fatalf("NewKey() err = nil, want error")
			}
		})
	}
}

func TestJWTRSSignerKeyManagerNewKeyDataFailsWithNilKeyFormat(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	if _, err := km.NewKeyData(nil); err == nil {
		t.Fatalf("NewKeyData() err = nil, want error")
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Fatalf("NewKey() err = nil, want error")
	}
}

func TestJWTRSSignerKeyManagerNewKeyDataFailsWithInvalidSerializedKeyFormat(t *testing.T) {
	km, err := registry.GetKeyManager(testJWTRSSignerKeyType)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testJWTRSSignerKeyType, err)
	}
	if _, err := km.NewKeyData([]byte("invalid_data")); err == nil {
		t.Fatalf("NewKeyData() err = nil, want error")
	}
	if _, err := km.NewKey([]byte("invalid_data")); err == nil {
		t.Fatalf("NewKey() err = nil, want error")
	}
}
