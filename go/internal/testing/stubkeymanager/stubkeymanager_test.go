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

package stubkeymanager_test

import (
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

func TestStubKeyManagerReturnsAppropiateValues(t *testing.T) {
	keyType := "some.key.type"
	km := stubkeymanager.StubKeyManager{
		URL:  keyType,
		Key:  &agpb.AesGcmKey{Version: 1, KeyValue: []byte("key_value")},
		Prim: &fakePrimitive{Name: "fake-primitive-name"},
		KeyData: &tpb.KeyData{
			TypeUrl:         keyType,
			Value:           []byte("key_value"),
			KeyMaterialType: tpb.KeyData_ASYMMETRIC_PRIVATE,
		},
	}
	if !km.DoesSupport(keyType) {
		t.Errorf("km.DoesSupport(%q) = false , want true", keyType)
	}
	if km.DoesSupport("some.other.key.type") {
		t.Errorf("km.DoesSupport(%q) = true , want false", keyType)
	}
	if km.TypeURL() != keyType {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), keyType)
	}
	key, err := km.NewKey(nil)
	if err != nil {
		t.Errorf("km.NewKey() err = %v, want nil", err)
	}
	if !cmp.Equal(key, km.Key, protocmp.Transform()) {
		t.Errorf("NewKey() = %v, want %v", key, km.Key)
	}
	keyData, err := km.NewKeyData(nil)
	if err != nil {
		t.Errorf("km.NewKeyData() err = %v, want nil", err)
	}
	if !cmp.Equal(keyData, km.KeyData, protocmp.Transform()) {
		t.Errorf("NewKeyData() = %v, want %v", keyData, km.KeyData)
	}
	p, err := km.Primitive(nil)
	if err != nil {
		t.Errorf("km.Primitive() err = %v, want nil", err)
	}
	if !cmp.Equal(p, km.Prim) {
		t.Errorf("Primitive() = %v, want %v", p, km.Prim)
	}
}
