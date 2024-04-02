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

package stubkeymanager_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/google/tink/go/internal/testing/stubkeymanager"
	agpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	tpb "github.com/google/tink/go/proto/tink_go_proto"
)

type fakePrimitive struct {
	Name string
}

func TestStubKeyManager(t *testing.T) {
	keyType := "some.key.type"
	km := stubkeymanager.StubKeyManager{
		URL:  keyType,
		Key:  &agpb.AesGcmKey{Version: 1, KeyValue: []byte("key_value")},
		Prim: &fakePrimitive{Name: "fake-primitive-name"},
		KeyData: &tpb.KeyData{
			TypeUrl:         keyType,
			Value:           []byte("key_value"),
			KeyMaterialType: tpb.KeyData_SYMMETRIC,
		},
	}
	if !km.DoesSupport(keyType) {
		t.Errorf("DoesSupport(%q) = false , want true", keyType)
	}
	if km.DoesSupport("some.other.key.type") {
		t.Errorf("DoesSupport(%q) = true , want false", keyType)
	}
	if km.TypeURL() != km.URL {
		t.Errorf("TypeURL() = %q, want %q", km.TypeURL(), keyType)
	}
	key, err := km.NewKey(nil)
	if err != nil {
		t.Errorf("NewKey() err = %v, want nil", err)
	}
	if !cmp.Equal(key, km.Key, protocmp.Transform()) {
		t.Errorf("NewKey() = %v, want %v", key, km.Key)
	}
	keyData, err := km.NewKeyData(nil)
	if err != nil {
		t.Errorf("NewKeyData() err = %v, want nil", err)
	}
	if !cmp.Equal(keyData, km.KeyData, protocmp.Transform()) {
		t.Errorf("NewKeyData() = %v, want %v", keyData, km.KeyData)
	}
	p, err := km.Primitive(nil)
	if err != nil {
		t.Errorf("Primitive() err = %v, want nil", err)
	}
	if !cmp.Equal(p, km.Prim) {
		t.Errorf("Primitive() = %v, want %v", p, km.Prim)
	}
}

func TestStubPrivateKeyManager(t *testing.T) {
	km := stubkeymanager.StubPrivateKeyManager{
		PubKeyData: &tpb.KeyData{
			TypeUrl:         "some.key.type",
			Value:           []byte("key_value"),
			KeyMaterialType: tpb.KeyData_ASYMMETRIC_PUBLIC,
		},
	}
	pubKeyData, err := km.PublicKeyData(nil)
	if err != nil {
		t.Errorf("PublicKeyData() err = %v, want nil", err)
	}
	if !cmp.Equal(pubKeyData, km.PubKeyData, protocmp.Transform()) {
		t.Errorf("PublicKeyData() = %v, want %v", pubKeyData, km.PubKeyData)
	}
}

func TestStubDerivableKeyManager(t *testing.T) {
	km := stubkeymanager.StubDerivableKeyManager{
		KeyMatType: tpb.KeyData_SYMMETRIC,
		DerKey:     &agpb.AesGcmKey{Version: 0, KeyValue: []byte("derived_key_value")},
		DerErr:     errors.New("hiya"),
	}
	if km.KeyMaterialType() != km.KeyMatType {
		t.Errorf("KeyMaterialType() = %d, want %d", km.KeyMaterialType(), tpb.KeyData_SYMMETRIC)
	}
	derivedKey, err := km.DeriveKey([]byte{}, &bytes.Buffer{})
	if !cmp.Equal(derivedKey, km.DerKey, protocmp.Transform()) {
		t.Errorf("DeriveKey() = %v, want %v", derivedKey, km.DerKey)
	}
	if err != km.DerErr {
		t.Errorf("DeriveKey() err = %v, want %v", err, km.DerErr)
	}
}
