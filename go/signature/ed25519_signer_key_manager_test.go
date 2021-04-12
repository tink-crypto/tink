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
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestED25519SignerGetPrimitiveBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}
	pvtKey := testutil.NewED25519PrivateKey()
	serializedKey, _ := proto.Marshal(pvtKey)
	tmp, err := km.Primitive(serializedKey)
	if err != nil {
		t.Errorf("unexpect error in test case: %s ", err)
	}
	var s = tmp.(*subtle.ED25519Signer)

	kmPub, err := registry.GetKeyManager(testutil.ED25519VerifierTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}
	pubKey := pvtKey.PublicKey
	serializedKey, _ = proto.Marshal(pubKey)
	tmp, err = kmPub.Primitive(serializedKey)
	if err != nil {
		t.Errorf("unexpect error in test case: %s ", err)
	}
	var v = tmp.(*subtle.ED25519Verifier)

	data := random.GetRandomBytes(1281)
	signature, err := s.Sign(data)
	if err != nil {
		t.Errorf("unexpected error when signing: %s", err)
	}

	if err := v.Verify(signature, data); err != nil {
		t.Errorf("unexpected error when verifying signature: %s", err)
	}

}

func TestED25519SignGetPrimitiveWithInvalidInput(t *testing.T) {
	// invalid params
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}

	// invalid version
	key := testutil.NewED25519PrivateKey()
	key.Version = testutil.ED25519SignerKeyVersion + 1
	serializedKey, _ := proto.Marshal(key)
	if _, err := km.Primitive(serializedKey); err == nil {
		t.Errorf("expect an error when version is invalid")
	}
	// nil input
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}

func TestED25519SignNewKeyBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}
	serializedFormat, _ := proto.Marshal(testutil.NewED25519PrivateKey())
	tmp, err := km.NewKey(serializedFormat)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	key := tmp.(*ed25519pb.Ed25519PrivateKey)
	if err := validateED25519PrivateKey(key); err != nil {
		t.Errorf("invalid private key in test case: %s", err)
	}
}

func TestED25519PublicKeyDataBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}
	pkm, ok := km.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("cannot obtain private key manager")
	}

	key := testutil.NewED25519PrivateKey()
	serializedKey, _ := proto.Marshal(key)

	pubKeyData, err := pkm.PublicKeyData(serializedKey)
	if err != nil {
		t.Errorf("unexpect error in test case: %s ", err)
	}
	if pubKeyData.TypeUrl != testutil.ED25519VerifierTypeURL {
		t.Errorf("incorrect type url: %s", pubKeyData.TypeUrl)
	}
	if pubKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
		t.Errorf("incorrect key material type: %d", pubKeyData.KeyMaterialType)
	}
	pubKey := new(ed25519pb.Ed25519PublicKey)
	if err = proto.Unmarshal(pubKeyData.Value, pubKey); err != nil {
		t.Errorf("invalid public key: %s", err)
	}
}

func TestED25519PublicKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ED25519SignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Signer key manager: %s", err)
	}
	pkm, ok := km.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("cannot obtain private key manager")
	}
	// modified key
	key := testutil.NewED25519PrivateKey()
	serializedKey, _ := proto.Marshal(key)
	serializedKey[0] = 0
	if _, err := pkm.PublicKeyData(serializedKey); err == nil {
		t.Errorf("expect an error when input is a modified serialized key")
	}
	// nil
	if _, err := pkm.PublicKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty slice
	if _, err := pkm.PublicKeyData([]byte{}); err == nil {
		t.Errorf("expect an error when input is an empty slice")
	}
}

func validateED25519PrivateKey(key *ed25519pb.Ed25519PrivateKey) error {
	if key.Version != testutil.ED25519SignerKeyVersion {
		return fmt.Errorf("incorrect private key's version: expect %d, got %d",
			testutil.ED25519SignerKeyVersion, key.Version)
	}
	publicKey := key.PublicKey
	if publicKey.Version != testutil.ED25519SignerKeyVersion {
		return fmt.Errorf("incorrect public key's version: expect %d, got %d",
			testutil.ED25519SignerKeyVersion, key.Version)
	}

	signer, err := subtle.NewED25519Signer(key.KeyValue)
	if err != nil {
		return fmt.Errorf("unexpected error when creating ED25519Sign: %s", err)
	}

	verifier, err := subtle.NewED25519Verifier(publicKey.KeyValue)
	if err != nil {
		return fmt.Errorf("unexpected error when creating ED25519Verify: %s", err)
	}
	for i := 0; i < 100; i++ {
		data := random.GetRandomBytes(1281)
		signature, err := signer.Sign(data)
		if err != nil {
			return fmt.Errorf("unexpected error when signing: %s", err)
		}

		if err := verifier.Verify(signature, data); err != nil {
			return fmt.Errorf("unexpected error when verifying signature: %s", err)
		}
	}
	return nil
}
