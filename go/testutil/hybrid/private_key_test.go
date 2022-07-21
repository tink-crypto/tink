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

package hybrid_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	testutilhybrid "github.com/google/tink/go/testutil/hybrid"
	hpkepb "github.com/google/tink/go/proto/hpke_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKeysetHandleFromSerializedPrivateKey(t *testing.T) {
	// Obtain private and public key handles via key template.
	keyTemplate := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template()
	privHandle, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		t.Fatalf("NewHandle(%v) err = %v, want nil", keyTemplate, err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("Public() err = %v, want nil", err)
	}

	// Get private, public key bytes and construct a private key handle.
	privKeyBytes, pubKeyBytes := privPubKeyBytes(t, privHandle)
	gotprivHandle, err := testutilhybrid.KeysetHandleFromSerializedPrivateKey(privKeyBytes, pubKeyBytes, keyTemplate)
	if err != nil {
		t.Errorf("KeysetHandleFromSerializedPrivateKey(%v, %v, %v) err = %v, want nil", privKeyBytes, pubKeyBytes, keyTemplate, err)
	}

	plaintext := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)

	// Encrypt with original public key handle.
	enc, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("NewHybridEncrypt(%v) err = %v, want nil", pubHandle, err)
	}
	ciphertext, err := enc.Encrypt(plaintext, ctxInfo)
	if err != nil {
		t.Fatalf("Encrypt(%x, %x) err = %v, want nil", plaintext, ctxInfo, err)
	}

	// Decrypt with private key handle constructed from key bytes.
	dec, err := hybrid.NewHybridDecrypt(gotprivHandle)
	if err != nil {
		t.Fatalf("NewHybridDecrypt(%v) err = %v, want nil", gotprivHandle, err)
	}
	gotPlaintext, err := dec.Decrypt(ciphertext, ctxInfo)
	if err != nil {
		t.Fatalf("Decrypt(%x, %x) err = %v, want nil", ciphertext, ctxInfo, err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("Decrypt(%x, %x) = %x, want %x", ciphertext, ctxInfo, gotPlaintext, plaintext)
	}
}

func TestKeysetHandleFromSerializedPrivateKeyInvalidTemplateFails(t *testing.T) {
	keyTemplate := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template()
	privHandle, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		t.Fatalf("NewHandle(%v) err = %v, want nil", keyTemplate, err)
	}
	privKeyBytes, pubKeyBytes := privPubKeyBytes(t, privHandle)

	tests := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{"AES_128_GCM", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template()},
		{"AES_128_GCM_Raw", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Raw_Key_Template()},
		{"AES_256_GCM", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template()},
		{"AES_256_GCM_Raw", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Raw_Key_Template()},
		{"CHACHA20_POLY1305", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template()},
		{"invalid type URL", &tinkpb.KeyTemplate{
			TypeUrl:          "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
			Value:            keyTemplate.GetValue(),
			OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := testutilhybrid.KeysetHandleFromSerializedPrivateKey(privKeyBytes, pubKeyBytes, test.template); err == nil {
				t.Errorf("KeysetHandleFromSerializedPrivateKey(%v, %v, %v) err = nil, want error", privKeyBytes, pubKeyBytes, test.template)
			}
		})
	}
}

func privPubKeyBytes(t *testing.T, handle *keyset.Handle) ([]byte, []byte) {
	t.Helper()

	// Write Handle to MemReaderWriter.
	got := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(handle, got); err != nil {
		t.Fatalf("Write(%v) err = %v, want nil", handle, err)
	}
	if len(got.Keyset.GetKey()) != 1 {
		t.Fatalf("len(gotPriv.Keyset) = %d", len(got.Keyset.GetKey()))
	}

	// Extract HpkePrivateKey from MemReaderWriter.
	serializedPrivKey := got.Keyset.GetKey()[0].GetKeyData().GetValue()
	privKey := &hpkepb.HpkePrivateKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		t.Fatalf("Unmarshal(%v) = err %v, want nil", serializedPrivKey, err)
	}

	return privKey.GetPrivateKey(), privKey.GetPublicKey().GetPublicKey()
}
