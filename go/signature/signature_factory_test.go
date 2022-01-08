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
	pubKeysetHandle, _ := testkeyset.NewHandle(pubKeyset)

	// sign some random data
	signer, err := signature.NewSigner(privKeysetHandle)
	if err != nil {
		t.Errorf("getting sign primitive failed: %s", err)
	}
	data := random.GetRandomBytes(1211)
	sig, err := signer.Sign(data)
	if err != nil {
		t.Errorf("signing failed: %s", err)
	}
	// verify with the same set of public keys should work
	verifier, err := signature.NewVerifier(pubKeysetHandle)
	if err != nil {
		t.Errorf("getting verify primitive failed: %s", err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Errorf("verification failed: %s", err)
	}
	// verify with random key should fail
	_, randomPub := newECDSAKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	pubKeys = []*tinkpb.Keyset_Key{randomPub}
	pubKeyset = testutil.NewKeyset(pubKeys[0].KeyId, pubKeys)
	pubKeysetHandle, _ = testkeyset.NewHandle(pubKeyset)
	verifier, err = signature.NewVerifier(pubKeysetHandle)
	if err != nil {
		t.Errorf("getting verify primitive failed: %s", err)
	}
	if err = verifier.Verify(sig, data); err == nil {
		t.Errorf("verification with random key should fail: %s", err)
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
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = signature.NewSigner(wrongKH)
	if err == nil {
		t.Error("calling NewSigner() with wrong *keyset.Handle should fail")
	}

	_, err = signature.NewVerifier(wrongKH)
	if err == nil {
		t.Error("calling NewVerifier() with wrong *keyset.Handle should fail")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = signature.NewSigner(goodKH)
	if err != nil {
		t.Errorf("calling NewSigner() with good *keyset.Handle failed: %s", err)
	}

	goodPublicKH, err := goodKH.Public()
	if err != nil {
		t.Errorf("failed to get public key: %s", err)
	}

	_, err = signature.NewVerifier(goodPublicKH)
	if err != nil {
		t.Errorf("calling NewVerifier() with good *keyset.Handle failed: %s", err)
	}
}
