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
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"

	jwtmacpb "github.com/google/tink/go/proto/jwt_hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func newJWTHMACKey(algorithm jwtmacpb.JwtHmacAlgorithm, kid *jwtmacpb.JwtHmacKey_CustomKid) *jwtmacpb.JwtHmacKey {
	return &jwtmacpb.JwtHmacKey{
		Version:   0,
		Algorithm: algorithm,
		KeyValue:  random.GetRandomBytes(32),
		CustomKid: kid,
	}
}

func newKeyData(key *jwtmacpb.JwtHmacKey) (*tinkpb.KeyData, error) {
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtHmacKey",
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

func createJWTMAC(keyData *tinkpb.KeyData, prefixType tinkpb.OutputPrefixType) (jwt.MAC, error) {
	handle, err := testkeyset.NewHandle(testutil.NewTestKeyset(keyData, prefixType))
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle: %v", err)
	}
	return jwt.NewMAC(handle)
}

func verifyMACCompareSubject(p jwt.MAC, compact string, validator *jwt.Validator, wantSubject string) error {
	verifiedJWT, err := p.VerifyMACAndDecode(compact, validator)
	if err != nil {
		return fmt.Errorf("p.VerifyMACAndDecode() err = %v, want nil", err)
	}
	subject, err := verifiedJWT.Subject()
	if err != nil {
		return fmt.Errorf("verifiedJWT.Subject() err = %v, want nil", err)
	}
	if subject != wantSubject {
		return fmt.Errorf("verifiedJWT.Subject() = %q, want %q", subject, wantSubject)
	}
	return nil
}

func TestNilKeyHandle(t *testing.T) {
	if _, err := jwt.NewMAC(nil); err == nil {
		t.Errorf("TestNilKeyHandle(nil) err = nil, want error")
	}
}

func TestFactorySameKeyMaterialWithRawPrefixAndNoKIDShouldIgnoreHeader(t *testing.T) {
	keyData, err := newKeyData(newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil))
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewJWTValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewJWTValidator() err = %v, want nil", err)
	}
	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if err := verifyMACCompareSubject(p, compact, validator, "tink-subject"); err != nil {
		t.Error(err)
	}
	p, err = createJWTMAC(keyData, tinkpb.OutputPrefixType_RAW)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err != nil {
		t.Errorf("VerifyMACAndDecode() with a RAW key err = %v, want nil", err)
	}
}

func TestFactorySameKeyMaterialWithDifferentPrefixAndKIDShouldFailVerification(t *testing.T) {
	key := newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil)
	keyData, err := newKeyData(key)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewJWTValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewJWTValidator() err = %v, want nil", err)
	}
	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if err := verifyMACCompareSubject(p, compact, validator, "tink-subject"); err != nil {
		t.Error(err)
	}
	key.CustomKid = &jwtmacpb.JwtHmacKey_CustomKid{
		Value: "custom-kid",
	}
	rawKeyData, err := newKeyData(key)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err = createJWTMAC(rawKeyData, tinkpb.OutputPrefixType_RAW)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err == nil {
		t.Errorf("VerifyMACAndDecode() with a different KID = nil, want error")
	}
}

func TestFactoryDifferentKeyShouldFailValidation(t *testing.T) {
	keyData, err := newKeyData(newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil))
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewJWTValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewJWTValidator() err = %v, want nil", err)
	}
	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if err := verifyMACCompareSubject(p, compact, validator, "tink-subject"); err != nil {
		t.Error(err)
	}
	diffKey := newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil)
	diffKeyData, err := newKeyData(diffKey)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err = createJWTMAC(diffKeyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err == nil {
		t.Errorf("VerifyMACAndDecode() with a different key = nil, want error")
	}
}

func TestFactoryWithRAWKeyAndKID(t *testing.T) {
	key := newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, &jwtmacpb.JwtHmacKey_CustomKid{Value: "custom-123"})
	keyData, err := newKeyData(key)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	ks := testutil.NewTestKeyset(keyData, tinkpb.OutputPrefixType_RAW)
	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("creating keyset handle: %v", err)
	}
	p, err := jwt.NewMAC(handle)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("NewRawJWT() err = %v, want nil", err)
	}

	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	validator, err := jwt.NewJWTValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("NewJWTValidator() err = %v, want nil", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err != nil {
		t.Errorf("p.VerifyMACAndDecode() err = %v, want nil", err)
	}
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}
	if _, err = jwt.NewMAC(kh); err == nil {
		t.Fatal("calling NewMAC() err = nil, want error")
	}
}
