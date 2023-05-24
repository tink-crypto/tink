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
//
////////////////////////////////////////////////////////////////////////////////

package registry_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/internal/tinkerror"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	customTypeURL = "type.googleapis.com/google.crypto.tink.CustomAesGcmKey"
)

// customKeyManager is a custom implementation of registry.KeyManager for AES GCM 128.
type customKeyManager struct{}

// Assert that customKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*customKeyManager)(nil)

func (km *customKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	key := new(wrapperspb.BytesValue)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("invalid key")
	}
	if len(key.GetValue()) != 16 {
		return nil, fmt.Errorf("invalid key")
	}
	return subtle.NewAESGCM(key.GetValue())
}

// NewKey is only used by registry.NewKey, and that function is only used by KMSEnvelopeAEAD.
// So there is no need to implement it.
func (km *customKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("not implemented")
}

func (km *customKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	keyFormat := new(wrapperspb.StringValue)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("invalid key format")
	}
	if keyFormat.GetValue() != "AEAD_AES_GCM_128" {
		return nil, fmt.Errorf("invalid key format")
	}
	keyValue := random.GetRandomBytes(16)
	key := &wrapperspb.BytesValue{
		Value: keyValue,
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         customTypeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

func (km *customKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == customTypeURL
}

func (km *customKeyManager) TypeURL() string {
	return customTypeURL
}

func (km *customKeyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_SYMMETRIC
}

// aesGCM128KeyTemplate creates a AES GCM 128 KeyTemplate for customKeyManager.
func aesGCM128KeyTemplate() *tinkpb.KeyTemplate {
	format := &wrapperspb.StringValue{
		Value: "AEAD_AES_GCM_128",
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          customTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}

// aesGCM128KeyToKeysetHandle creates a keyset.Handle with one custom AES GCM 128 key.
func aesGCM128KeyToKeysetHandle(rawAESKey []byte, keyID uint32, prefixType tinkpb.OutputPrefixType) (*keyset.Handle, error) {
	if len(rawAESKey) != 16 {
		return nil, fmt.Errorf("invalid key length")
	}
	key := &wrapperspb.BytesValue{Value: rawAESKey}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	keyData := &tinkpb.KeyData{
		TypeUrl:         customTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	ks := &tinkpb.Keyset{
		PrimaryKeyId: keyID,
		Key: []*tinkpb.Keyset_Key{
			&tinkpb.Keyset_Key{
				KeyData:          keyData,
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            keyID,
				OutputPrefixType: prefixType,
			},
		},
	}
	serializedKeyset, err := proto.Marshal(ks)
	if err != nil {
		return nil, err
	}
	return insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(serializedKeyset)))
}

func TestCreateEncryptDecrypt(t *testing.T) {
	handle, err := keyset.NewHandle(aesGCM128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aesGCM128KeyTemplate()) err = %v, want nil", err)
	}
	primitive, err := aead.New(handle)
	if err != nil {
		t.Fatalf("aead.New(handle) err = %v, want nil", err)
	}

	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")

	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("primitive.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}
	decrypted, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("primitive.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("primitive.Decrypt(ciphertext, associatedData) = %q, want: %q", decrypted, plaintext)
	}
}

func TestImportExistingKeyDecryptsExistingCiphertext(t *testing.T) {
	rawAesKey := random.GetRandomBytes(16)
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")

	// Create a AES GCM 128 ciphertext using rawAesKey.
	aesGCMForRawAesKey, err := subtle.NewAESGCM(rawAesKey)
	if err != nil {
		t.Fatalf("subtle.NewAESGCM(rawAesKey) err = %v, want nil", err)
	}
	ciphertext, err := aesGCMForRawAesKey.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("aesGCMForRawAesKey.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}

	// Import rawAesKey into a Tink keyset.Handle, and decrypt the ciphertext.
	handle, err := aesGCM128KeyToKeysetHandle(rawAesKey, 123, tinkpb.OutputPrefixType_RAW)
	if err != nil {
		t.Fatalf("aesGCM128KeyToKeysetHandle() err = %v, want nil", err)
	}
	primitive, err := aead.New(handle)
	if err != nil {
		t.Fatalf("aead.New(handle) err = %v, want nil", err)
	}
	gotPlaintext, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("primitive.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(plaintext, gotPlaintext) {
		t.Fatalf("primitive.Decrypt(ciphertext, associatedData) = %q, want: %q", gotPlaintext, plaintext)
	}
}

func TestEncryptAndDecryptWithTinkPrefix(t *testing.T) {
	// Create an AEAD for rawAesKey with output prefix type TINK.
	rawAesKey := random.GetRandomBytes(16)
	handle, err := aesGCM128KeyToKeysetHandle(rawAesKey, 0x11223344, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("aesGCM128KeyToKeysetHandle() err = %v, want nil", err)
	}
	primitive, err := aead.New(handle)
	if err != nil {
		t.Fatalf("aead.New(handle) err = %v, want nil", err)
	}

	// Encrypt and decrypt.
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("primitive.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}
	gotPlaintext, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("primitive.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(plaintext, gotPlaintext) {
		t.Fatalf("primitive.Decrypt(ciphertext, associatedData) = %q, want: %q", gotPlaintext, plaintext)
	}

	// Check that ciphertext has the correct prefix.
	gotPrefix := ciphertext[:5]
	wantPrefix := []byte{0x01, 0x11, 0x22, 0x33, 0x44}
	if !bytes.Equal(gotPrefix, wantPrefix) {
		t.Fatalf("ciphertext[:5] = %q, want: %q", gotPrefix, wantPrefix)
	}

	// Check that subtle.NewAESGCM with rawAesKey can decrypt the ciphertext if the prefix is removed.
	aesGCMForRawAesKey, err := subtle.NewAESGCM(rawAesKey)
	if err != nil {
		t.Fatalf("subtle.NewAESGCM(rawAesKey) err = %v, want nil", err)
	}
	gotPlaintext, err = aesGCMForRawAesKey.Decrypt(ciphertext[5:], associatedData)
	if err != nil {
		t.Fatalf("aesGCMForRawAesKey.Decrypt() err = %v, want nil", err)
	}
	if !bytes.Equal(plaintext, gotPlaintext) {
		t.Fatalf("aesGCMForRawAesKey.Decrypt() = %q, want: %q", gotPlaintext, plaintext)
	}
}

func TestMixedKeysetWorks(t *testing.T) {
	rawAesKey := random.GetRandomBytes(16)

	// Create a AES GCM 128 ciphertext using rawAesKey.
	subtlePrimitive, err := subtle.NewAESGCM(rawAesKey)
	if err != nil {
		t.Fatalf("subtle.NewAESGCM(rawAesKey) err = %v, want nil", err)
	}
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := subtlePrimitive.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("subtlePrimitive.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}

	// Create handle2, which is a keyset.Handle that contains a customKeyManager key of rawAesKey and
	// a new, non-customKeyManager key.
	handle1, err := aesGCM128KeyToKeysetHandle(rawAesKey, 123, tinkpb.OutputPrefixType_RAW)
	if err != nil {
		t.Fatalf("aesGCM128KeyToKeysetHandle() err = %v, want nil", err)
	}
	manager := keyset.NewManagerFromHandle(handle1)
	keyID, err := manager.Add(aead.AES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add(aead.AES128CTRHMACSHA256KeyTemplate()) err = %v, want nil", err)
	}
	err = manager.SetPrimary(keyID)
	if err != nil {
		t.Fatalf("manager.SetPrimary(keyID) = %v", err)
	}
	handle2, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v", err)
	}

	primitive, err := aead.New(handle2)
	if err != nil {
		t.Fatalf("aead.New(handle2) err = %v", err)
	}
	gotPlaintext, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("primitive.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(plaintext, gotPlaintext) {
		t.Errorf("primitive.Decrypt(ciphertext, associatedData) = %q, want: %q", gotPlaintext, plaintext)
	}
}

func TestSerializeAndParseKeysetWorks(t *testing.T) {
	handle, err := keyset.NewHandle(aesGCM128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aesGCM128KeyTemplate()) err = %v, want nil", err)
	}
	primitive, err := aead.New(handle)
	if err != nil {
		t.Fatalf("aead.New(handle) err = %v, want nil", err)
	}

	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("primitive.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}

	// Serialize the keyset.
	buff := &bytes.Buffer{}
	err = insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)) = %v, want nil", err)
	}
	serializedKeyset := buff.Bytes()

	// Parse the keyset.
	parsedHandle, err := insecurecleartextkeyset.Read(
		keyset.NewBinaryReader(bytes.NewBuffer(serializedKeyset)))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(serializedKeyset))) = %v, want nil", err)
	}

	primitive2, err := aead.New(parsedHandle)
	if err != nil {
		t.Fatalf("aead.New(parsedHandle) err = %v, want nil", err)
	}

	gotPlaintext, err := primitive2.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("primitive2.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(plaintext, gotPlaintext) {
		t.Errorf("primitive2.Decrypt(ciphertext, associatedData) = %q, want: %q", gotPlaintext, plaintext)
	}
}

func init() { registry.RegisterKeyManager(&customKeyManager{}) }
