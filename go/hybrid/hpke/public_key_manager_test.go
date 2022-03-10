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

package hpke

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/subtle/random"
	pb "github.com/google/tink/go/proto/hpke_go_proto"
)

func TestPublicKeyManagerPrimitiveInvalidKeyVersion(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	pubKey, _ := pubPrivKeys(t, validParams(t))
	pubKey.Version = publicKeyKeyVersion + 1
	invalidPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(invalidPubKey); err == nil {
		t.Error("Primitive(invalidPubKey) err = nil, want error")
	}
}

func TestPublicKeyManagerPrimitiveUnknownKEM(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	params := validParams(t)
	params.Kem = pb.HpkeKem_KEM_UNKNOWN
	pubKey, _ := pubPrivKeys(t, params)
	invalidPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(invalidPubKey); err == nil {
		t.Error("Primitive(invalidPubKey) err = nil, want error")
	}
}

func TestPublicKeyManagerPrimitiveUnknownKDF(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	params := validParams(t)
	params.Kdf = pb.HpkeKdf_KDF_UNKNOWN
	pubKey, _ := pubPrivKeys(t, params)
	invalidPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(invalidPubKey); err == nil {
		t.Error("Primitive(invalidPubKey) err = nil, want error")
	}
}

func TestPublicKeyManagerPrimitiveUnknownAEAD(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	params := validParams(t)
	params.Aead = pb.HpkeAead_AEAD_UNKNOWN
	pubKey, _ := pubPrivKeys(t, params)
	invalidPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(invalidPubKey); err == nil {
		t.Error("Primitive(invalidPubKey) err = nil, want error")
	}
}

func TestPublicKeyManagerPrimitiveMissingParams(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	pubKey, _ := pubPrivKeys(t, nil)
	invalidPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Primitive(invalidPubKey); err == nil {
		t.Error("Primitive(invalidPubKey) err = nil, want error")
	}
}

func TestPublicKeyManagerPrimitiveNilKey(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	if _, err := km.Primitive(nil); err == nil {
		t.Error("Primitive(nil) err = nil, want error")
	}
}

func TestPublicKeyManagerPrimitiveEncryptDecrypt(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}

	wantPT := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)

	aeadIDs := []pb.HpkeAead{pb.HpkeAead_AES_128_GCM, pb.HpkeAead_AES_256_GCM}
	for _, aeadID := range aeadIDs {
		params := &pb.HpkeParams{
			Kem:  pb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
			Kdf:  pb.HpkeKdf_HKDF_SHA256,
			Aead: aeadID,
		}
		pubKey, privKey := pubPrivKeys(t, params)
		serializedPubKey, err := proto.Marshal(pubKey)
		if err != nil {
			t.Fatal(err)
		}

		e, err := km.Primitive(serializedPubKey)
		if err != nil {
			t.Fatalf("Primitive(serializedPubKey) err = %v, want nil", err)
		}
		enc, ok := e.(*Encrypt)
		if !ok {
			t.Fatal("primitive is not Encrypt")
		}
		dec, err := newDecrypt(privKey)
		if err != nil {
			t.Fatalf("newDecrypt(privKey) err = %v, want nil", err)
		}

		ct, err := enc.Encrypt(wantPT, ctxInfo)
		if err != nil {
			t.Fatalf("Encrypt(wantPT, ctxInfo) err = %v, want nil", err)
		}
		gotPT, err := dec.Decrypt(ct, ctxInfo)
		if err != nil {
			t.Fatalf("Decrypt(ct, ctxInfo) err = %v, want nil", err)
		}
		if !bytes.Equal(gotPT, wantPT) {
			t.Errorf("Decrypt(gotPT, wantPT) = %x, want %x", gotPT, wantPT)
		}
	}
}

func TestPublicKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	if !km.DoesSupport(publicKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = false, want true", publicKeyTypeURL)
	}
	unsupportedKeyTypeURL := "unsupported.key.type"
	if km.DoesSupport(unsupportedKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = true, want false", unsupportedKeyTypeURL)
	}
}

func TestPublicKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	if km.TypeURL() != publicKeyTypeURL {
		t.Errorf("TypeURL = %q, want %q", km.TypeURL(), publicKeyTypeURL)
	}
}

func TestPublicKeyManagerNotSupported(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	if _, err := km.NewKey(nil); err != errNotSupported {
		t.Fatalf("NewKey(nil) err = %v, want %v", err, errNotSupported)
	}
	if _, err := km.NewKeyData(nil); err != errNotSupported {
		t.Fatalf("NewKeyData(nil) err = %v, want %v", err, errNotSupported)
	}
}
