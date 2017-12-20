// Copyright 2017 Google Inc.
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
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/signature/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink/tink"
	"github.com/google/tink/go/util/testutil"
	"github.com/google/tink/go/util/util"
	commonpb "github.com/google/tink/proto/common_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"testing"
)

func TestPublicKeySignFactoryInstance(t *testing.T) {
	f := signature.PublicKeySignFactory()
	if f == nil {
		t.Errorf("PublicKeySignFactory() returns nil")
	}
}

func TestPublicKeySignVerifyFactory(t *testing.T) {
	signature.PublicKeyVerifyConfig().RegisterStandardKeyTypes()
	signature.PublicKeySignConfig().RegisterStandardKeyTypes()
	tinkPriv, tinkPub := newEcdsaKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	legacyPriv, legacyPub := newEcdsaKeysetKeypair(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		tinkpb.OutputPrefixType_LEGACY,
		2)
	rawPriv, rawPub := newEcdsaKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		tinkpb.OutputPrefixType_RAW,
		3)
	crunchyPriv, crunchyPub := newEcdsaKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		tinkpb.OutputPrefixType_CRUNCHY,
		4)
	privKeys := []*tinkpb.Keyset_Key{tinkPriv, legacyPriv, rawPriv, crunchyPriv}
	privKeyset := util.NewKeyset(privKeys[0].KeyId, privKeys)
	privKeysetHandle, _ := tink.CleartextKeysetHandle().ParseKeyset(privKeyset)
	pubKeys := []*tinkpb.Keyset_Key{tinkPub, legacyPub, rawPub, crunchyPub}
	pubKeyset := util.NewKeyset(pubKeys[0].KeyId, pubKeys)
	pubKeysetHandle, _ := tink.CleartextKeysetHandle().ParseKeyset(pubKeyset)

	// sign some random data
	signer, err := signature.PublicKeySignFactory().GetPrimitive(privKeysetHandle)
	if err != nil {
		t.Errorf("getting sign primitive failed: %s", err)
	}
	data := random.GetRandomBytes(1211)
	sig, err := signer.Sign(data)
	if err != nil {
		t.Errorf("signing failed: %s", err)
	}
	// verify with the same set of public keys should work
	verifier, err := signature.PublicKeyVerifyFactory().GetPrimitive(pubKeysetHandle)
	if err != nil {
		t.Errorf("getting verify primitive failed: %s", err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Errorf("verification failed: %s", err)
	}
	// verify with random key should fail
	_, randomPub := newEcdsaKeysetKeypair(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	pubKeys = []*tinkpb.Keyset_Key{randomPub}
	pubKeyset = util.NewKeyset(pubKeys[0].KeyId, pubKeys)
	pubKeysetHandle, _ = tink.CleartextKeysetHandle().ParseKeyset(pubKeyset)
	verifier, err = signature.PublicKeyVerifyFactory().GetPrimitive(pubKeysetHandle)
	if err != nil {
		t.Errorf("getting verify primitive failed: %s", err)
	}
	if err := verifier.Verify(sig, data); err == nil {
		t.Errorf("verification with random key should fail: %s", err)
	}
}

func newEcdsaKeysetKeypair(hashType commonpb.HashType,
	curve commonpb.EllipticCurveType,
	outputPrefixType tinkpb.OutputPrefixType,
	keyId uint32) (*tinkpb.Keyset_Key, *tinkpb.Keyset_Key) {
	key := testutil.NewEcdsaPrivateKey(hashType, curve)
	serializedKey, _ := proto.Marshal(key)
	keyData := util.NewKeyData(signature.ECDSA_SIGN_TYPE_URL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	privKey := util.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyId, outputPrefixType)

	serializedKey, _ = proto.Marshal(key.PublicKey)
	keyData = util.NewKeyData(signature.ECDSA_VERIFY_TYPE_URL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	pubKey := util.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyId, outputPrefixType)
	return privKey, pubKey
}
