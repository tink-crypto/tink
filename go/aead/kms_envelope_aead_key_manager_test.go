// Copyright 2023 Google LLC
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

package aead_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testing/fakekms"
	"github.com/google/tink/go/testutil"
	ctrpb "github.com/google/tink/go/proto/aes_ctr_go_proto"
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_aead_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	kmsenvpb "github.com/google/tink/go/proto/kms_envelope_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestNewKMSEnvelopeAEADKeyWithInvalidDEK(t *testing.T) {
	keyURI, err := fakekms.NewKeyURI()
	if err != nil {
		t.Fatalf("fakekms.NewKeyURI() err = %v", err)
	}

	// Create a KmsEnvelopeAeadKeyFormat with a DekTemplate that is not supported.
	format := &kmsenvpb.KmsEnvelopeAeadKeyFormat{
		KekUri:      keyURI,
		DekTemplate: mac.HMACSHA256Tag128KeyTemplate(),
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("failed to marshal key format: %s", err)
	}
	keyTemplate := &tinkpb.KeyTemplate{
		Value:            serializedFormat,
		TypeUrl:          testutil.KMSEnvelopeAEADTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}

	_, err = keyset.NewHandle(keyTemplate)
	if err == nil {
		t.Errorf("keyset.NewHandle(keyTemplate) err = nil, want error")
	}
}

func TestNewKMSEnvelopeAEADKeyWithInvalidSerializedKeyFormat(t *testing.T) {
	keyURI, err := fakekms.NewKeyURI()
	if err != nil {
		t.Fatalf("fakekms.NewKeyURI() err = %v", err)
	}
	fakeClient, err := fakekms.NewClient(keyURI)
	if err != nil {
		t.Fatalf("fakekms.NewClient() err = %v", err)
	}
	registry.RegisterKMSClient(fakeClient)
	defer registry.ClearKMSClients()

	// Create DEK template with unset embedded key parameters.
	dekFormat := &ctrhmacpb.AesCtrHmacAeadKeyFormat{
		AesCtrKeyFormat: &ctrpb.AesCtrKeyFormat{
			Params:  nil,
			KeySize: 32,
		},
		HmacKeyFormat: &hmacpb.HmacKeyFormat{
			Params:  nil,
			KeySize: 32,
		},
	}
	serializedDEKFormat, err := proto.Marshal(dekFormat)
	if err != nil {
		t.Fatalf("failed to marshal key format: %s", err)
	}
	dekTemplate := &tinkpb.KeyTemplate{
		Value:            serializedDEKFormat,
		TypeUrl:          testutil.AESCTRHMACAEADTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}

	format := &kmsenvpb.KmsEnvelopeAeadKeyFormat{
		KekUri:      keyURI,
		DekTemplate: dekTemplate,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("failed to marshal key format: %s", err)
	}
	keyTemplate := &tinkpb.KeyTemplate{
		Value:            serializedFormat,
		TypeUrl:          testutil.KMSEnvelopeAEADTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}

	// Currently, the DEK template isn't checked for validatiy during creation
	// of a KMSEnvelopeAEAD key. It's only exercised when a cryptographic
	// operation is attempted.
	//
	// TODO(ckl): Rework if DEK template is exercised during initialization.
	handle, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		t.Fatalf("keyset.NewHandle(keyTemplate) err = %v, want nil", err)
	}

	a, err := aead.New(handle)
	if err != nil {
		t.Fatalf("handle.NewAEAD(keyURI) err = %v, want nil", err)
	}

	_, err = a.Encrypt([]byte{}, []byte{})
	if err == nil {
		t.Errorf("a.Encrypt() err = nil, want error")
	}
}

func TestKMSEnvelopeAEADWithTinkPrefix(t *testing.T) {
	keyURI := "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"
	client, err := fakekms.NewClient(keyURI)
	if err != nil {
		t.Fatal(err)
	}
	registry.RegisterKMSClient(client)
	defer registry.ClearKMSClients()

	// Keyset that was created with
	// aead.CreateKMSEnvelopeAEADKeyTemplate(keyURI, aead.AES256GCMKeyTemplate()), and then serialized
	// with Tink's JSON keyset witer. Then, the output prefix type was changed from "RAW" to "TINK".
	jsonKeysetWithTinkPrefix := `{"primaryKeyId":3980895889, "key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey", "value":"EsMBCoYBZmFrZS1rbXM6Ly9DTTJiM19NREVsUUtTQW93ZEhsd1pTNW5iMjluYkdWaGNHbHpMbU52YlM5bmIyOW5iR1V1WTNKNWNIUnZMblJwYm1zdVFXVnpSMk50UzJWNUVoSWFFSUs3NXQ1TC1hZGxVd1ZoV3ZSdVdVd1lBUkFCR00yYjNfTURJQUUSOAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EgIQIBgB", "keyMaterialType":"REMOTE"}, "status":"ENABLED", "keyId":3980895889, "outputPrefixType":"TINK"}]}`

	parsedHandle, err := insecurecleartextkeyset.Read(
		keyset.NewJSONReader(bytes.NewBuffer([]byte(jsonKeysetWithTinkPrefix))))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}

	primitive, err := aead.New(parsedHandle)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("message")
	associatedData := []byte("example KMS envelope AEAD encryption")

	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}
	gotPlaintext, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("got plaintext %q, want %q", gotPlaintext, plaintext)
	}

	// Also verify that the ciphertext has a TINK prefix
	gotPrefix := ciphertext[:5]
	// The Tink prefix is 0x01 followed by the 4 bytes key ID. The key ID is 3980895889, which is
	// equal to 0xed47a691.
	wantPrefix := []byte{0x01, 0xed, 0x47, 0xa6, 0x91}
	if !bytes.Equal(gotPrefix, wantPrefix) {
		t.Fatalf("ciphertext[:5] = %q, want %q", gotPrefix, wantPrefix)
	}

}
