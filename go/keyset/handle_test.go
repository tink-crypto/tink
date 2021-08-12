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
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestNewHandle(t *testing.T) {
	kt := mac.HMACSHA256Tag128KeyTemplate()
	kh, err := keyset.NewHandle(kt)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	ks := testkeyset.KeysetMaterial(kh)
	if len(ks.Key) != 1 {
		t.Errorf("incorrect number of keys in the keyset: %d", len(ks.Key))
	}
	key := ks.Key[0]
	if ks.PrimaryKeyId != key.KeyId {
		t.Errorf("incorrect primary key id, expect %d, got %d", key.KeyId, ks.PrimaryKeyId)
	}
	if key.KeyData.TypeUrl != kt.TypeUrl {
		t.Errorf("incorrect type url, expect %s, got %s", kt.TypeUrl, key.KeyData.TypeUrl)
	}
	if _, err = mac.New(kh); err != nil {
		t.Errorf("cannot get primitive from generated keyset handle: %s", err)
	}
}

func TestNewHandleWithInvalidInput(t *testing.T) {
	// template unregistered TypeUrl
	template := mac.HMACSHA256Tag128KeyTemplate()
	template.TypeUrl = "some unknown TypeUrl"
	if _, err := keyset.NewHandle(template); err == nil {
		t.Errorf("expect an error when TypeUrl is not registered")
	}
	// nil
	if _, err := keyset.NewHandle(nil); err == nil {
		t.Errorf("expect an error when template is nil")
	}
}

func TestRead(t *testing.T) {
	masterKey, err := subtle.NewAESGCM([]byte(strings.Repeat("A", 32)))
	if err != nil {
		t.Errorf("subtle.NewAESGCM(): %v", err)
	}

	// Create a keyset
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	ks := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, _ := testkeyset.NewHandle(ks)

	memKeyset := &keyset.MemReaderWriter{}
	if err := h.Write(memKeyset, masterKey); err != nil {
		t.Fatalf("handle.Write(): %v", err)
	}
	h2, err := keyset.Read(memKeyset, masterKey)
	if err != nil {
		t.Fatalf("keyset.Read(): %v", err)
	}
	if !proto.Equal(testkeyset.KeysetMaterial(h), testkeyset.KeysetMaterial(h2)) {
		t.Fatalf("Decrypt failed: got %v, want %v", h2, h)
	}
}

func TestReadWithAssociatedData(t *testing.T) {
	masterKey, err := subtle.NewAESGCM([]byte(strings.Repeat("A", 32)))
	if err != nil {
		t.Fatalf("subtle.NewAESGCM(): %v", err)
	}

	// Create a keyset
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keySet := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	handle, _ := testkeyset.NewHandle(keySet)

	memKeyset := &keyset.MemReaderWriter{}
	if err := handle.WriteWithAssociatedData(memKeyset, masterKey, []byte{0x01, 0x02}); err != nil {
		t.Fatalf("handle.Write(): %v", err)
	}
	handle2, err := keyset.ReadWithAssociatedData(memKeyset, masterKey, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("keyset.Read(): %v", err)
	}
	if !proto.Equal(testkeyset.KeysetMaterial(handle), testkeyset.KeysetMaterial(handle2)) {
		t.Errorf("Decrypt failed: got %v, want %v", handle2, handle)
	}
}

func TestReadWithMismatchedAssociatedData(t *testing.T) {
	masterKey, err := subtle.NewAESGCM([]byte(strings.Repeat("A", 32)))
	if err != nil {
		t.Fatalf("subtle.NewAESGCM(): %v", err)
	}

	// Create a keyset
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keySet := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	handle, _ := testkeyset.NewHandle(keySet)

	memKeyset := &keyset.MemReaderWriter{}
	if err := handle.WriteWithAssociatedData(memKeyset, masterKey, []byte{0x01, 0x02}); err != nil {
		t.Fatalf("handle.Write(): %v", err)
	}
	_, err = keyset.ReadWithAssociatedData(memKeyset, masterKey, []byte{0x01, 0x03})
	if err == nil {
		t.Fatalf("keyset.Read() was expected to fail")
	}
}

func TestReadWithNoSecrets(t *testing.T) {
	// Create a keyset containing public key material
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	ks := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, _ := testkeyset.NewHandle(ks)

	memKeyset := &keyset.MemReaderWriter{}
	if err := h.WriteWithNoSecrets(memKeyset); err != nil {
		t.Fatalf("handle.WriteWithNoSecrets(): %v", err)
	}
	h2, err := keyset.ReadWithNoSecrets(memKeyset)
	if err != nil {
		t.Fatalf("keyset.ReadWithNoSecrets(): %v", err)
	}
	if !proto.Equal(testkeyset.KeysetMaterial(h), testkeyset.KeysetMaterial(h2)) {
		t.Fatalf("Decrypt failed: got %v, want %v", h2, h)
	}
}

func TestWithNoSecretsFunctionsFailWhenHandlingSecretKeyMaterial(t *testing.T) {
	// Create a keyset containing secret key material (symmetric)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	ks := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, _ := testkeyset.NewHandle(ks)

	if err := h.WriteWithNoSecrets(&keyset.MemReaderWriter{}); err == nil {
		t.Error("handle.WriteWithNoSecrets() should fail when exporting secret key material")
	}

	if _, err := keyset.ReadWithNoSecrets(&keyset.MemReaderWriter{Keyset: testkeyset.KeysetMaterial(h)}); err == nil {
		t.Error("keyset.ReadWithNoSecrets should fail when importing secret key material")
	}
}

func TestWithNoSecretsFunctionsFailWhenUnknownKeyMaterial(t *testing.T) {
	// Create a keyset containing secret key material (symmetric)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_UNKNOWN_KEYMATERIAL)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	ks := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, _ := testkeyset.NewHandle(ks)

	if err := h.WriteWithNoSecrets(&keyset.MemReaderWriter{}); err == nil {
		t.Error("handle.WriteWithNoSecrets() should fail when exporting secret key material")
	}

	if _, err := keyset.ReadWithNoSecrets(&keyset.MemReaderWriter{Keyset: testkeyset.KeysetMaterial(h)}); err == nil {
		t.Error("keyset.ReadWithNoSecrets should fail when importing secret key material")
	}
}

func TestWithNoSecretsFunctionsFailWithAsymmetricPrivateKeyMaterial(t *testing.T) {
	// Create a keyset containing secret key material (asymmetric)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	ks := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, _ := testkeyset.NewHandle(ks)

	if err := h.WriteWithNoSecrets(&keyset.MemReaderWriter{}); err == nil {
		t.Error("handle.WriteWithNoSecrets() should fail when exporting secret key material")
	}

	if _, err := keyset.ReadWithNoSecrets(&keyset.MemReaderWriter{Keyset: testkeyset.KeysetMaterial(h)}); err == nil {
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

func TestKeysetHandleString(t *testing.T) {
	jsonKeyset := `{"primaryKeyId":42,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"a2V5X3ZhbHVlOiJceDExXHhhMnY/XHgwYj5UXHhkZU5QXHgwODM8XHhjYl0wIg==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":42,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesEaxKey","value":"cGFyYW1zOntoYXNoOlNIQTUxMiAgdGFnX3NpemU6MzJ9ICBrZXlfdmFsdWU6Ilx4YTTdl1ZceGYzXHgxMlx4ZjdceGI2Nlx4YjdceGEyXHhjY1x4ZTd9XHgwN3tceGZlNzFceGJjIg==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":711,"outputPrefixType":"RAW"}]}`
	handle, err := testkeyset.Read(keyset.NewJSONReader(bytes.NewBufferString(jsonKeyset)))
	if err != nil {
		t.Fatalf("testkeyset.Read failed: %v", err)
	}
	expected := `primary_key_id:42 key_info:{type_url:"type.googleapis.com/google.crypto.tink.AesGcmKey" status:ENABLED key_id:42 output_prefix_type:TINK} key_info:{type_url:"type.googleapis.com/google.crypto.tink.AesEaxKey" status:ENABLED key_id:711 output_prefix_type:RAW}`
	if handle.String() != expected {
		t.Fatalf("output is not equal, got %s, want %s", handle.String(), expected)
	}
}
