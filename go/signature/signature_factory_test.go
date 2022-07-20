// Copyright 2018 Google LLC
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

package signature_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestSignerVerifyFactory(t *testing.T) {
	tinkPriv, tinkPub := newECDSAKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	legacyPriv, legacyPub := newECDSAKeysetKeypair(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		tinkpb.OutputPrefixType_LEGACY,
		2)
	rawPriv, rawPub := newECDSAKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		tinkpb.OutputPrefixType_RAW,
		3)
	crunchyPriv, crunchyPub := newECDSAKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		tinkpb.OutputPrefixType_CRUNCHY,
		4)
	privKeys := []*tinkpb.Keyset_Key{tinkPriv, legacyPriv, rawPriv, crunchyPriv}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	privKeysetHandle, _ := testkeyset.NewHandle(privKeyset)
	pubKeys := []*tinkpb.Keyset_Key{tinkPub, legacyPub, rawPub, crunchyPub}
	pubKeyset := testutil.NewKeyset(pubKeys[0].KeyId, pubKeys)
	pubKeysetHandle, err := testkeyset.NewHandle(pubKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(pubKeyset) err = %v, want nil", err)
	}
	// sign some random data
	signer, err := signature.NewSigner(privKeysetHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privKeysetHandle) err = %v, want nil", err)
	}
	data := random.GetRandomBytes(1211)
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign(data) err = %v, want nil", err)
	}
	// verify with the same set of public keys should work
	verifier, err := signature.NewVerifier(pubKeysetHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(pubKeysetHandle) err = %v, want nil", err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Errorf("verifier.Verify(sig, data) = %v, want nil", err)
	}
	// verify with other key should fail
	_, otherPub := newECDSAKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	otherPubKeys := []*tinkpb.Keyset_Key{otherPub}
	otherPubKeyset := testutil.NewKeyset(otherPubKeys[0].KeyId, otherPubKeys)
	otherPubKeysetHandle, err := testkeyset.NewHandle(otherPubKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(otherPubKeyset) err = %v, want nil", err)
	}
	otherVerifier, err := signature.NewVerifier(otherPubKeysetHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(otherPubKeysetHandle) err = %v, want nil", err)
	}
	if err = otherVerifier.Verify(sig, data); err == nil {
		t.Error("otherVerifier.Verify(sig, data) = nil, want not nil")
	}
}

func TestPrimitiveFactoryFailsWhenKeysetHasNoPrimary(t *testing.T) {
	privateKey, _ := newECDSAKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	privateKeysetWithoutPrimary := &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{privateKey},
	}
	privateHandleWithoutPrimary, err := testkeyset.NewHandle(privateKeysetWithoutPrimary)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(privateKeysetWithoutPrimary) err = %v, want nil", err)
	}
	publicHandleWithoutPrimary, err := privateHandleWithoutPrimary.Public()
	if err != nil {
		t.Fatalf("privateHandleWithoutPrimary.Public() err = %v, want nil", err)
	}

	if _, err = signature.NewSigner(privateHandleWithoutPrimary); err == nil {
		t.Errorf("signature.NewSigner(privateHandleWithoutPrimary) err = nil, want not nil")
	}

	if _, err = signature.NewVerifier(publicHandleWithoutPrimary); err == nil {
		t.Errorf("signature.NewVerifier(publicHandleWithoutPrimary) err = nil, want not nil")
	}
}

func newECDSAKeysetKeypair(hashType commonpb.HashType,
	curve commonpb.EllipticCurveType,
	outputPrefixType tinkpb.OutputPrefixType,
	keyID uint32) (*tinkpb.Keyset_Key, *tinkpb.Keyset_Key) {
	key := testutil.NewRandomECDSAPrivateKey(hashType, curve)
	serializedKey, _ := proto.Marshal(key)
	keyData := testutil.NewKeyData(testutil.ECDSASignerTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	privKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefixType)

	serializedKey, _ = proto.Marshal(key.PublicKey)
	keyData = testutil.NewKeyData(testutil.ECDSAVerifierTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	pubKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefixType)
	return privKey, pubKey
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}

	_, err = signature.NewSigner(wrongKH)
	if err == nil {
		t.Error("signature.NewSigner(wrongKH) err = nil, want not nil")
	}

	_, err = signature.NewVerifier(wrongKH)
	if err == nil {
		t.Error("signature.NewVerifier(wrongKH) err = nil, want not nil")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}

	_, err = signature.NewSigner(goodKH)
	if err != nil {
		t.Fatalf("signature.NewSigner(goodKH) err = %v, want nil", err)
	}

	goodPublicKH, err := goodKH.Public()
	if err != nil {
		t.Fatalf("goodKH.Public() err = %v, want nil", err)
	}

	_, err = signature.NewVerifier(goodPublicKH)
	if err != nil {
		t.Errorf("signature.NewVerifier(goodPublicKH) err = %v, want nil", err)
	}
}
