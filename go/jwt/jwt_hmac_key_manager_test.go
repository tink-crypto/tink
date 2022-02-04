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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/subtle/random"
	jwtmacpb "github.com/google/tink/go/proto/jwt_hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

type jwtKeyManagerTestCase struct {
	tag       string
	keyFormat *jwtmacpb.JwtHmacKeyFormat
	key       *jwtmacpb.JwtHmacKey
}

const (
	typeURL = "type.googleapis.com/google.crypto.tink.JwtHmacKey"
)

func generateKeyFormat(keySize uint32, algorithm jwtmacpb.JwtHmacAlgorithm) *jwtmacpb.JwtHmacKeyFormat {
	return &jwtmacpb.JwtHmacKeyFormat{
		KeySize:   keySize,
		Algorithm: algorithm,
	}
}

func TestDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q) error = %v, want nil", typeURL, err)
	}
	if !km.DoesSupport(typeURL) {
		t.Errorf("km.DoesSupport(%q) = false, want true", typeURL)
	}
}

func TestTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q) error = %v, want nil", typeURL, err)
	}
	if km.TypeURL() != typeURL {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), typeURL)
	}
}

var invalidKeyFormatTestCases = []jwtKeyManagerTestCase{
	{
		tag:       "invalid hash algorithm",
		keyFormat: generateKeyFormat(32, jwtmacpb.JwtHmacAlgorithm_HS_UNKNOWN),
	},
	{
		tag:       "invalid key size",
		keyFormat: generateKeyFormat(31, jwtmacpb.JwtHmacAlgorithm_HS256),
	},
	{
		tag:       "empty key format",
		keyFormat: &jwtmacpb.JwtHmacKeyFormat{},
	},
	{
		tag:       "nil key format",
		keyFormat: nil,
	},
}

func TestNewKeyInvalidFormatFails(t *testing.T) {
	for _, tc := range invalidKeyFormatTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			if _, err := km.NewKey(serializedKeyFormat); err == nil {
				t.Errorf("km.NewKey() err = nil, want error")
			}
		})
	}
}

func TestNewDataInvalidFormatFails(t *testing.T) {
	for _, tc := range invalidKeyFormatTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			if _, err := km.NewKeyData(serializedKeyFormat); err == nil {
				t.Errorf("km.NewKey() err = nil, want error")
			}
		})
	}
}

var validKeyFormatTestCases = []jwtKeyManagerTestCase{
	{
		tag:       "SHA256 hash algorithm",
		keyFormat: generateKeyFormat(32, jwtmacpb.JwtHmacAlgorithm_HS256),
	},
	{
		tag:       "SHA384 hash algorithm",
		keyFormat: generateKeyFormat(48, jwtmacpb.JwtHmacAlgorithm_HS384),
	},
	{
		tag:       "SHA512 hash algorithm",
		keyFormat: generateKeyFormat(48, jwtmacpb.JwtHmacAlgorithm_HS512),
	},
}

func TestNewKey(t *testing.T) {
	for _, tc := range validKeyFormatTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			k, err := km.NewKey(serializedKeyFormat)
			if err != nil {
				t.Errorf("km.NewKey() err = %v, want nil", err)
			}
			key, ok := k.(*jwtmacpb.JwtHmacKey)
			if !ok {
				t.Errorf("key isn't of type JwtHmacKey")
			}
			if key.Algorithm != tc.keyFormat.Algorithm {
				t.Errorf("k.Algorithm = %v, want %v", key.Algorithm, tc.keyFormat.Algorithm)
			}
			if len(key.KeyValue) != int(tc.keyFormat.KeySize) {
				t.Errorf("len(key.KeyValue) = %d, want %d", len(key.KeyValue), tc.keyFormat.KeySize)
			}
		})
	}
}

func TestNewKeyData(t *testing.T) {
	for _, tc := range validKeyFormatTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKeyFormat, err := proto.Marshal(tc.keyFormat)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			k, err := km.NewKeyData(serializedKeyFormat)
			if err != nil {
				t.Errorf("km.NewKeyData() err = %v, want nil", err)
			}
			if k.GetTypeUrl() != typeURL {
				t.Errorf("k.GetTypeUrl() = %q, want %q", k.GetTypeUrl(), typeURL)
			}
			if k.GetKeyMaterialType() != tinkpb.KeyData_SYMMETRIC {
				t.Errorf("k.GetKeyMaterialType() = %q, want %q", k.GetKeyMaterialType(), tinkpb.KeyData_SYMMETRIC)
			}
		})
	}
}

func generateKey(keySize, version uint32, algorithm jwtmacpb.JwtHmacAlgorithm, kid *jwtmacpb.JwtHmacKey_CustomKid) *jwtmacpb.JwtHmacKey {
	return &jwtmacpb.JwtHmacKey{
		KeyValue:  random.GetRandomBytes(keySize),
		Algorithm: algorithm,
		CustomKid: kid,
		Version:   version,
	}
}

func TestGetPrimitiveWithValidKeys(t *testing.T) {
	rawJWT, err := NewRawJWT(&RawJWTOptions{WithoutExpiration: true, Audiences: []string{"tink-aud"}})
	if err != nil {
		t.Fatalf("NewRawJWT() err = %v, want nil", err)
	}
	validator, err := NewJWTValidator(&ValidatorOpts{AllowMissingExpiration: true, ExpectedAudiences: refString("tink-aud")})
	if err != nil {
		t.Fatalf("NewJWTValidator() err = %v, want nil", err)
	}
	for _, tc := range []jwtKeyManagerTestCase{
		{
			tag: "SHA256 hash algorithm",
			key: generateKey(32, 0, jwtmacpb.JwtHmacAlgorithm_HS256, nil),
		},
		{
			tag: "SHA384 hash algorithm",
			key: generateKey(48, 0, jwtmacpb.JwtHmacAlgorithm_HS384, nil),
		},
		{
			tag: "SHA512 hash algorithm",
			key: generateKey(64, 0, jwtmacpb.JwtHmacAlgorithm_HS512, nil),
		},
		{
			tag: "with custom kid",
			key: generateKey(64, 0, jwtmacpb.JwtHmacAlgorithm_HS512, &jwtmacpb.JwtHmacKey_CustomKid{Value: "1235"}),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKey, err := proto.Marshal(tc.key)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			p, err := km.Primitive(serializedKey)
			if err != nil {
				t.Errorf("km.Primitive() err = %v, want nil", err)
			}
			primitive, ok := p.(*macWithKID)
			if !ok {
				t.Errorf("primitive isn't of type: macWithKID")
			}
			compact, err := primitive.ComputeMACAndEncodeWithKID(rawJWT, nil)
			if err != nil {
				t.Errorf("ComputeMACAndEncodeWithKID() err = %v, want nil", err)
			}
			verifiedJWT, err := primitive.VerifyMACAndDecodeWithKID(compact, validator, nil)
			if err != nil {
				t.Errorf("VerifyMACAndDecodeWithKID() err = %v, want nil", err)
			}
			audiences, err := verifiedJWT.Audiences()
			if err != nil {
				t.Errorf("verifiedJWT.Audiences() err = %v, want nil", err)
			}
			if !cmp.Equal(audiences, []string{"tink-aud"}) {
				t.Errorf("verifiedJWT.Audiences() = %q, want ['tink-aud']", audiences)
			}

		})
	}
}

func TestSpecyfingCustomKIDAndTINKKIDFails(t *testing.T) {
	// key and compact are examples from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
	compact := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rawKey, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
	if err != nil {
		t.Fatalf("failed decoding test key: %v", err)
	}
	key := &jwtmacpb.JwtHmacKey{
		KeyValue:  rawKey,
		Algorithm: jwtmacpb.JwtHmacAlgorithm_HS256,
		CustomKid: &jwtmacpb.JwtHmacKey_CustomKid{Value: "1235"},
		Version:   0,
	}
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Errorf("serializing key format: %v", err)
	}
	p, err := km.Primitive(serializedKey)
	if err != nil {
		t.Errorf("km.Primitive() err = %v, want nil", err)
	}
	primitive, ok := p.(*macWithKID)
	if !ok {
		t.Errorf("primitive isn't of type: macWithKID")
	}

	rawJWT, err := NewRawJWT(&RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Errorf("creating new RawJWT: %v", err)
	}
	opts := &ValidatorOpts{
		ExpectedTypeHeader: refString("JWT"),
		ExpectedIssuer:     refString("joe"),
		FixedNow:           time.Unix(12345, 0),
	}
	validator, err := NewJWTValidator(opts)
	if err != nil {
		t.Errorf("creating new JWTValidator: %v", err)
	}
	if _, err := primitive.ComputeMACAndEncodeWithKID(rawJWT, refString("4566")); err == nil {
		t.Errorf("primitive.ComputeMACAndEncodeWithKID() err = nil, want error")
	}
	if _, err := primitive.VerifyMACAndDecodeWithKID(compact, validator, refString("4566")); err == nil {
		t.Errorf("primitive.VerifyMACAndDecodeWithKID(kid = 4566) err = nil, want error")
	}
	// Verify success without KID
	if _, err := primitive.VerifyMACAndDecodeWithKID(compact, validator, nil); err != nil {
		t.Errorf("primitive.VerifyMACAndDecodeWithKID(kid = nil) err = %v, want nil", err)
	}
}

func TestGetPrimitiveWithInvalidKeyFails(t *testing.T) {
	for _, tc := range []jwtKeyManagerTestCase{
		{
			tag: "empty key",
			key: &jwtmacpb.JwtHmacKey{},
		},
		{
			tag: "nil key",
			key: nil,
		},
		{
			tag: "unsupported hash algorithm",
			key: generateKey(32, 0, jwtmacpb.JwtHmacAlgorithm_HS_UNKNOWN, nil),
		},
		{
			tag: "short key length",
			key: generateKey(20, 0, jwtmacpb.JwtHmacAlgorithm_HS384, nil),
		},
		{
			tag: "unsupported version",
			key: generateKey(48, 1, jwtmacpb.JwtHmacAlgorithm_HS384, nil),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			km, err := registry.GetKeyManager(typeURL)
			if err != nil {
				t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
			}
			serializedKey, err := proto.Marshal(tc.key)
			if err != nil {
				t.Errorf("serializing key format: %v", err)
			}
			if _, err := km.Primitive(serializedKey); err == nil {
				t.Errorf("km.Primitive() err = nil, want error")
			}
		})
	}
}

func TestGeneratesDifferentKeys(t *testing.T) {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q): %v", typeURL, err)
	}
	serializedKeyFormat, err := proto.Marshal(generateKeyFormat(32, jwtmacpb.JwtHmacAlgorithm_HS256))
	if err != nil {
		t.Errorf("serializing key format: %v", err)
	}
	k1, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		t.Errorf("km.NewKey() err = %v, want nil", err)
	}
	k2, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		t.Errorf("km.NewKey() err = %v, want nil", err)
	}
	key1, ok := k1.(*jwtmacpb.JwtHmacKey)
	if !ok {
		t.Errorf("k1 isn't of type JwtHmacKey")
	}
	key2, ok := k2.(*jwtmacpb.JwtHmacKey)
	if !ok {
		t.Errorf("k2 isn't of type JwtHmacKey")
	}
	if cmp.Equal(key1.GetKeyValue(), key2.GetKeyValue()) {
		t.Errorf("key material should differ")
	}
}
