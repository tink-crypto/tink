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

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeysethandle"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	commonpb "github.com/google/tink/proto/common_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
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
	privKeyset := tink.CreateKeyset(privKeys[0].KeyId, privKeys)
	privKeysetHandle, _ := testkeysethandle.KeysetHandle(privKeyset)
	pubKeys := []*tinkpb.Keyset_Key{tinkPub, legacyPub, rawPub, crunchyPub}
	pubKeyset := tink.CreateKeyset(pubKeys[0].KeyId, pubKeys)
	pubKeysetHandle, _ := testkeysethandle.KeysetHandle(pubKeyset)

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
	pubKeyset = tink.CreateKeyset(pubKeys[0].KeyId, pubKeys)
	pubKeysetHandle, _ = testkeysethandle.KeysetHandle(pubKeyset)
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
	key := testutil.NewECDSAPrivateKey(hashType, curve)
	serializedKey, _ := proto.Marshal(key)
	keyData := tink.CreateKeyData(signature.ECDSASignerTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	privKey := tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefixType)

	serializedKey, _ = proto.Marshal(key.PublicKey)
	keyData = tink.CreateKeyData(signature.ECDSAVerifierTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	pubKey := tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefixType)
	return privKey, pubKey
}
