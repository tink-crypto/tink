// Copyright 2019 Google LLC
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

package keyset_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalapi"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestNewHandle(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Errorf("keyset.NewHandle(template) = %v, want nil", err)
	}
	ks := testkeyset.KeysetMaterial(handle)
	if len(ks.Key) != 1 {
		t.Errorf("len(ks.Key) = %d, want 1", len(ks.Key))
	}
	key := ks.Key[0]
	if ks.PrimaryKeyId != key.KeyId {
		t.Errorf("ks.PrimaryKeyId = %d, want %d", ks.PrimaryKeyId, key.KeyId)
	}
	if key.KeyData.TypeUrl != template.TypeUrl {
		t.Errorf("key.KeyData.TypeUrl = %v, want %v", key.KeyData.TypeUrl, template.TypeUrl)
	}
	if _, err = mac.New(handle); err != nil {
		t.Errorf("mac.New(handle) err = %v, want nil", err)
	}
}

func TestNewHandleWithInvalidTypeURLFails(t *testing.T) {
	// template with unknown TypeURL
	invalidTemplate := mac.HMACSHA256Tag128KeyTemplate()
	invalidTemplate.TypeUrl = "some unknown TypeURL"
	if _, err := keyset.NewHandle(invalidTemplate); err == nil {
		t.Errorf("keyset.NewHandle(invalidTemplate) err = nil, want error")
	}
}

func TestNewHandleWithNilTemplateFails(t *testing.T) {
	if _, err := keyset.NewHandle(nil); err == nil {
		t.Error("keyset.NewHandle(nil) err = nil, want error")
	}
}

func TestWriteAndReadInBinary(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	err = handle.Write(keyset.NewBinaryWriter(buff), keysetEncryptionAead)
	if err != nil {
		t.Fatalf("handle.Write(keyset.NewBinaryWriter(buff), keysetEncryptionAead) err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	gotHandle, err := keyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), keysetEncryptionAead)
	if err != nil {
		t.Fatalf("keyset.Read() err = %v, want nil", err)
	}

	if !proto.Equal(testkeyset.KeysetMaterial(gotHandle), testkeyset.KeysetMaterial(handle)) {
		t.Fatalf("keyset.Read() = %v, want %v", gotHandle, handle)
	}
}

func TestWriteAndReadInJSON(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	err = handle.Write(keyset.NewJSONWriter(buff), keysetEncryptionAead)
	if err != nil {
		t.Fatalf("h.Write(keyset.NewJSONWriter(buff), keysetEncryptionAead) err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	gotHandle, err := keyset.Read(keyset.NewJSONReader(bytes.NewBuffer(encrypted)), keysetEncryptionAead)
	if err != nil {
		t.Fatalf("keyset.Read() err = %v, want nil", err)
	}

	if !proto.Equal(testkeyset.KeysetMaterial(gotHandle), testkeyset.KeysetMaterial(handle)) {
		t.Fatalf("keyset.Read() = %v, want %v", gotHandle, handle)
	}
}

func TestWriteAndReadWithAssociatedData(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}
	associatedData := []byte{0x01, 0x02}

	buff := &bytes.Buffer{}
	err = handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), keysetEncryptionAead, associatedData)
	if err != nil {
		t.Fatalf("handle.WriteWithAssociatedData() err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	handle2, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), keysetEncryptionAead, associatedData)
	if err != nil {
		t.Fatalf("keyset.ReadWithAssociatedData() err = %v, want nil", err)
	}

	if !proto.Equal(testkeyset.KeysetMaterial(handle), testkeyset.KeysetMaterial(handle2)) {
		t.Errorf("keyset.ReadWithAssociatedData() = %v, want %v", handle2, handle)
	}
}

func TestReadWithMismatchedAssociatedData(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}
	associatedData := []byte{0x01, 0x02}

	buff := &bytes.Buffer{}
	err = handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), keysetEncryptionAead, associatedData)
	if err != nil {
		t.Fatalf("handle.WriteWithAssociatedData() err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	invalidAssociatedData := []byte{0x01, 0x03}
	_, err = keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), keysetEncryptionAead, invalidAssociatedData)
	if err == nil {
		t.Errorf("keyset.ReadWithAssociatedData() err = nil, want err")
	}
}

func TestWriteAndReadWithNoSecrets(t *testing.T) {
	// Create a keyset that contains a public key.
	privateHandle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}
	handle, err := privateHandle.Public()
	if err != nil {
		t.Fatalf("privateHandle.Public() err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	err = handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff))
	if err != nil {
		t.Fatalf("handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), masterKey, associatedData) err = %v, want nil", err)
	}
	serialized := buff.Bytes()

	handle2, err := keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err != nil {
		t.Fatalf("keyset.ReadWithNoSecrets() err = %v, want nil", err)
	}

	if !proto.Equal(testkeyset.KeysetMaterial(handle), testkeyset.KeysetMaterial(handle2)) {
		t.Fatalf("keyset.ReadWithNoSecrets() = %v, want %v", handle2, handle)
	}
}

func TestWriteWithNoSecretsFailsWithSymmetricSecretKey(t *testing.T) {
	// Create a keyset that contains a symmetric secret key.
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES256GCMKeyTemplate()) err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	err = handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff))
	if err == nil {
		t.Error("handle.WriteWithNoSecrets() = nil, want error")
	}
}

func TestReadWithNoSecretsFailsWithSymmetricSecretKey(t *testing.T) {
	// Create a keyset that contains a symmetric secret key.
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES256GCMKeyTemplate()) err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	err = testkeyset.Write(handle, keyset.NewBinaryWriter(buff))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)) err = %v, want nil", err)
	}
	serialized := buff.Bytes()

	_, err = keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err == nil {
		t.Error("keyset.ReadWithNoSecrets() = nil, want error")
	}
}

func TestWriteWithNoSecretsFailsWithPrivateKey(t *testing.T) {
	// Create a keyset that contains a private key.
	handle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	if err := handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff)); err == nil {
		t.Error("handle.WriteWithNoSecrets() = nil, want error")
	}
}

func TestReadWithNoSecretsFailsWithPrivateKey(t *testing.T) {
	// Create a keyset that contains a private key.
	handle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	err = testkeyset.Write(handle, keyset.NewBinaryWriter(buff))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)) err = %v, want nil", err)
	}
	serialized := buff.Bytes()

	_, err = keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err == nil {
		t.Error("keyset.ReadWithNoSecrets() = nil, want error")
	}
}

func TestWriteAndReadWithNoSecretsFailsWithUnknownKeyMaterial(t *testing.T) {
	// Create a keyset that contains unknown key material.
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_UNKNOWN_KEYMATERIAL)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	ks := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := proto.Marshal(ks)
	if err != nil {
		t.Fatal(err)
	}

	buff := &bytes.Buffer{}
	err = handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff))
	if err == nil {
		t.Error("handle.WriteWithNoSecrets() = nil, want error")
	}

	_, err = keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err == nil {
		t.Error("handle.ReadWithNoSecrets() = nil, want error")
	}
}

func TestKeysetInfo(t *testing.T) {
	kt := mac.HMACSHA256Tag128KeyTemplate()
	kh, err := keyset.NewHandle(kt)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	info := kh.KeysetInfo()
	if info.PrimaryKeyId != info.KeyInfo[0].KeyId {
		t.Errorf("Expected primary key id: %d, but got: %d", info.KeyInfo[0].KeyId, info.PrimaryKeyId)
	}
}

func TestPrimitivesWithRegistry(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) err = %v, want nil", template, err)
	}
	handleMAC, err := mac.New(handle)
	if err != nil {
		t.Fatalf("mac.New(%v) err = %v, want nil", handle, err)
	}

	ks := testkeyset.KeysetMaterial(handle)
	if len(ks.Key) != 1 {
		t.Fatalf("len(ks.Key) = %d, want 1", len(ks.Key))
	}
	keyDataPrimitive, err := registry.PrimitiveFromKeyData(ks.Key[0].KeyData)
	if err != nil {
		t.Fatalf("registry.PrimitiveFromKeyData(%v) err = %v, want nil", ks.Key[0].KeyData, err)
	}
	keyDataMAC, ok := keyDataPrimitive.(tink.MAC)
	if !ok {
		t.Fatal("registry.PrimitiveFromKeyData(keyData) is not of type tink.MAC")
	}

	plaintext := []byte("plaintext")
	handleMACTag, err := handleMAC.ComputeMAC(plaintext)
	if err != nil {
		t.Fatalf("handleMAC.ComputeMAC(%v) err = %v, want nil", plaintext, err)
	}
	if err = keyDataMAC.VerifyMAC(handleMACTag, plaintext); err != nil {
		t.Errorf("keyDataMAC.VerifyMAC(%v, %v) err = %v, want nil", handleMACTag, plaintext, err)
	}
	keyDataMACTag, err := keyDataMAC.ComputeMAC(plaintext)
	if err != nil {
		t.Fatalf("keyDataMAC.ComputeMAC(%v) err = %v, want nil", plaintext, err)
	}
	if err = handleMAC.VerifyMAC(keyDataMACTag, plaintext); err != nil {
		t.Errorf("handleMAC.VerifyMAC(%v, %v) err = %v, want nil", keyDataMACTag, plaintext, err)
	}
}

type testConfig struct{}

func (c *testConfig) PrimitiveFromKeyData(_ *tinkpb.KeyData, _ internalapi.Token) (any, error) {
	return testPrimitive{}, nil
}

func TestPrimitivesWithConfig(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) = %v, want nil", template, err)
	}
	primitives, err := handle.Primitives(keyset.WithConfig(&testConfig{}))
	if err != nil {
		t.Fatalf("handle.Primitives(keyset.WithConfig(&testConfig{})) err = %v, want nil", err)
	}
	if len(primitives.EntriesInKeysetOrder) != 1 {
		t.Fatalf("len(handle.Primitives()) = %d, want 1", len(primitives.EntriesInKeysetOrder))
	}
	if _, ok := (primitives.Primary.Primitive).(testPrimitive); !ok {
		t.Errorf("handle.Primitives().Primary = %v, want instance of `testPrimitive`", primitives.Primary.Primitive)
	}
}

func TestPrimitivesWithMultipleConfigs(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) = %v, want nil", template, err)
	}
	_, err = handle.Primitives(keyset.WithConfig(&testConfig{}), keyset.WithConfig(&testConfig{}))
	if err == nil { // if NO error
		t.Error("handle.Primitives(keyset.WithConfig(&testConfig{}), keyset.WithConfig(&testConfig{})) err = nil, want error")
	}
}

type testKeyManager struct{}

type testPrimitive struct{}

func (km *testKeyManager) Primitive(_ []byte) (any, error)              { return testPrimitive{}, nil }
func (km *testKeyManager) NewKey(_ []byte) (proto.Message, error)       { return nil, nil }
func (km *testKeyManager) TypeURL() string                              { return mac.HMACSHA256Tag128KeyTemplate().TypeUrl }
func (km *testKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) { return nil, nil }
func (km *testKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == mac.HMACSHA256Tag128KeyTemplate().TypeUrl
}

func TestPrimitivesWithKeyManager(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) = %v, want nil", template, err)
	}

	// Verify that without providing a custom key manager we get a usual MAC.
	if _, err = mac.New(handle); err != nil {
		t.Fatalf("mac.New(%v) err = %v, want nil", handle, err)
	}

	// Verify that with the custom key manager provided we get the custom primitive.
	primitives, err := handle.PrimitivesWithKeyManager(&testKeyManager{})
	if err != nil {
		t.Fatalf("handle.PrimitivesWithKeyManager(testKeyManager) err = %v, want nil", err)
	}
	if len(primitives.EntriesInKeysetOrder) != 1 {
		t.Fatalf("len(handle.PrimitivesWithKeyManager()) = %d, want 1", len(primitives.EntriesInKeysetOrder))
	}
	if _, ok := (primitives.Primary.Primitive).(testPrimitive); !ok {
		t.Errorf("handle.PrimitivesWithKeyManager().Primary = %v, want instance of `testPrimitive`", primitives.Primary.Primitive)
	}
}
