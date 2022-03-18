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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	jepb "github.com/google/tink/go/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestSignerVerifierFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}
	if _, err := jwt.NewSigner(kh); err == nil {
		t.Errorf("jwt.NewSigner() err = nil, want error")
	}
	if _, err := jwt.NewVerifier(kh); err == nil {
		t.Errorf("jwt.NewVerifier() err = nil, want error")
	}
}

func TestSignerVerifierFactoryNilKeyset(t *testing.T) {
	if _, err := jwt.NewSigner(nil); err == nil {
		t.Errorf("jwt.NewSigner(nil) err = nil, want error")
	}
	if _, err := jwt.NewVerifier(nil); err == nil {
		t.Errorf("jwt.NewVerifier(nil) err = nil, want error")
	}
}

func createJWTECDSAKey(kid *string) (*jepb.JwtEcdsaPrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey(curve=P256): %v", err)
	}
	var customKID *jepb.JwtEcdsaPublicKey_CustomKid = nil
	if kid != nil {
		customKID = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *kid}
	}
	return &jepb.JwtEcdsaPrivateKey{
		Version: 0,
		PublicKey: &jepb.JwtEcdsaPublicKey{
			Version:   0,
			Algorithm: jepb.JwtEcdsaAlgorithm_ES256,
			X:         k.X.Bytes(),
			Y:         k.Y.Bytes(),
			CustomKid: customKID,
		},
		KeyValue: k.D.Bytes(),
	}, nil
}

func createKeyData(privKey *jepb.JwtEcdsaPrivateKey) (*tinkpb.KeyData, error) {
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		return nil, fmt.Errorf("serializing private key proto: %v", err)
	}
	return &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
		Value:           serializedPrivKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func createKeysetHandles(privKey *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType) (*keyset.Handle, *keyset.Handle, error) {
	k := testutil.NewKey(privKey, tinkpb.KeyStatusType_ENABLED, 1 /*=keyID*/, outputPrefixType)
	privKeyHandle, err := testkeyset.NewHandle(testutil.NewKeyset(k.KeyId, []*tinkpb.Keyset_Key{k}))
	if err != nil {
		return nil, nil, fmt.Errorf("creating keyset handle for private key: %v", err)
	}
	pubKeyHandle, err := privKeyHandle.Public()
	if err != nil {
		return nil, nil, fmt.Errorf("creating keyset handle for public key: %v", err)
	}
	return privKeyHandle, pubKeyHandle, nil
}

func createKeyHandlesFromKey(t *testing.T, privKey *jepb.JwtEcdsaPrivateKey, outputPrefixType tinkpb.OutputPrefixType) (*keyset.Handle, *keyset.Handle) {
	privKeyData, err := createKeyData(privKey)
	if err != nil {
		t.Fatal(err)
	}
	privKeyHandle, pubKeyHandle, err := createKeysetHandles(privKeyData, outputPrefixType)
	if err != nil {
		t.Fatal(err)
	}
	return privKeyHandle, pubKeyHandle
}

func createKeyAndKeyHandles(t *testing.T, kid *string, outputPrefixType tinkpb.OutputPrefixType) (*jepb.JwtEcdsaPrivateKey, *keyset.Handle, *keyset.Handle) {
	privKey, err := createJWTECDSAKey(kid)
	if err != nil {
		t.Fatal(err)
	}
	privKeyHandle, pubKeyHandle := createKeyHandlesFromKey(t, privKey, outputPrefixType)
	return privKey, privKeyHandle, pubKeyHandle
}

func TestFactoryVerifyWithDifferentKeyFails(t *testing.T) {
	_, privKeyHandle, pubKeyHandle := createKeyAndKeyHandles(t, nil /*=kid*/, tinkpb.OutputPrefixType_TINK)

	signer, err := jwt.NewSigner(privKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Audiences: []string{"tink-audience"}})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true, ExpectedAudiences: refString("tink-audience")})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}

	// verification with different key fails
	_, _, pubKeyHandle = createKeyAndKeyHandles(t, nil /*=kid*/, tinkpb.OutputPrefixType_TINK)
	verifier, err = jwt.NewVerifier(pubKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err == nil {
		t.Errorf("verifier.VerifyAndDecode() err = nil, want error")
	}
}

func TestFactorySignWithTinkAndCustomKIDFails(t *testing.T) {
	_, privKeyHandle, _ := createKeyAndKeyHandles(t, refString("customKID"), tinkpb.OutputPrefixType_TINK)
	signer, err := jwt.NewSigner(privKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	if _, err := signer.SignAndEncode(rawJWT); err == nil {
		t.Errorf("signer.SignAndEncode() err = nil, want error")
	}
}

type signerVerifierFactoryKIDTestCase struct {
	tag                  string
	signerOutputPrefix   tinkpb.OutputPrefixType
	signerKID            *string
	verifierOutputPrefix tinkpb.OutputPrefixType
	verifierKID          *string
}

func TestFactorySignVerifyWithKIDFailure(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	for _, tc := range []signerVerifierFactoryKIDTestCase{
		{
			tag:                  "raw output prefix and different custom kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          refString("OtherCustomKID"),
		},
		{
			tag:                  "verifier with tink output prefix and custom kid when token has no kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          refString("customKID"),
		},
		{
			tag:                  "verifier with tink output prefix and custom kid when token has kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          refString("customKid"),
		},
		{
			tag:                  "token with fixed kid and verifier with tink output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          nil,
		},
		{
			tag:                  "token missing kid in header when verifier has tink output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          nil,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			key, privKeyHandle, _ := createKeyAndKeyHandles(t, tc.signerKID, tc.signerOutputPrefix)
			signer, err := jwt.NewSigner(privKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
			}
			compact, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
			}

			key.PublicKey.CustomKid = nil
			if tc.verifierKID != nil {
				key.PublicKey.CustomKid = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *tc.verifierKID}
			}
			_, pubKeyHandle := createKeyHandlesFromKey(t, key, tc.verifierOutputPrefix)
			verifier, err := jwt.NewVerifier(pubKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(compact, validator); err == nil {
				t.Errorf("verifier.VerifyAndDecode() err = nil, want error")
			}
		})
	}
}

func TestFactorySignVerifyWithKIDSuccess(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	for _, tc := range []signerVerifierFactoryKIDTestCase{
		{
			tag:                "signer verifier without custom kid and with raw output prefix",
			signerOutputPrefix: tinkpb.OutputPrefixType_RAW,
			signerKID:          nil,

			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          nil,
		},
		{
			tag:                  "signer with custom kid verifier without custom kid and raw output prefixes",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          nil,
		},
		{
			tag:                  "signer and verifier same custom kid and raw output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          refString("customKID"),
		},
		{
			tag:                  "signer and verifier with tink output prefix and no custom kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_TINK,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          nil,
		},
		{
			tag:                  "signer with tink output prefix verifier with raw output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_TINK,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          nil,
		},
		{
			tag:                  "token missing kid in header when verifier has custom kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          refString("customKID"),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			key, privKeyHandle, _ := createKeyAndKeyHandles(t, tc.signerKID, tc.signerOutputPrefix)
			signer, err := jwt.NewSigner(privKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
			}
			compact, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
			}

			key.GetPublicKey().CustomKid = nil
			if tc.verifierKID != nil {
				key.GetPublicKey().CustomKid = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *tc.verifierKID}
			}
			_, pubKeyHandle := createKeyHandlesFromKey(t, key, tc.verifierOutputPrefix)
			verifier, err := jwt.NewVerifier(pubKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}
		})
	}
}
