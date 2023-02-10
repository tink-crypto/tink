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
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"

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
	// Create a keyset containing public key material
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

// TODO(b/268044921) Convert to table-driven test.
func TestWriteWithNoSecretsFailWhenHandlingSecretKeyMaterial(t *testing.T) {
	// Create a keyset containing secret key material (symmetric)
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES256GCMKeyTemplate()) err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	err = handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff))
	if err == nil {
		t.Error("handle.WriteWithNoSecrets() should fail when exporting secret key material")
	}
}

func TestReadWithNoSecretsFunctionsFailWhenHandlingSecretKeyMaterial(t *testing.T) {
	// Create a keyset containing secret key material (symmetric)
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
		t.Error("keyset.ReadWithNoSecrets should fail when importing secret key material")
	}
}

func TestWriteAndReadWithNoSecretsFailsWithUnknownKeyMaterial(t *testing.T) {
	// Create a keyset containing unknown key material
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
		t.Error("handle.WriteWithNoSecrets() should fail when exporting unknown key material")
	}

	_, err = keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err == nil {
		t.Error("keyset.ReadWithNoSecrets should fail when importing unknown key material")
	}
}

func TestWriteWithNoSecretsFunctionsFailWithAsymmetricPrivateKeyMaterial(t *testing.T) {
	// Create a keyset containing secret key material (asymmetric)
	handle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}

	if err := handle.WriteWithNoSecrets(&keyset.MemReaderWriter{}); err == nil {
		t.Error("handle.WriteWithNoSecrets() should fail when exporting secret key material")
	}
}

func TestWithNoSecretsFunctionsFailWithAsymmetricPrivateKeyMaterial(t *testing.T) {
	// Create a keyset containing secret key material (asymmetric)
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
		t.Error("keyset.ReadWithNoSecrets should fail when importing secret key material")
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
