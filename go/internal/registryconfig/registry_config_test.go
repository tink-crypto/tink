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
// /////////////////////////////////////////////////////////////////////////////

package registryconfig_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalapi"
	"github.com/google/tink/go/internal/registryconfig"
	"github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestPrimitiveFromKeyData(t *testing.T) {
	keyData := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
	registryConfig := &registryconfig.RegistryConfig{}
	p, err := registryConfig.PrimitiveFromKeyData(keyData, internalapi.Token{})
	if err != nil {
		t.Errorf("registryConfig.PrimitiveFromKeyData() err = %v, want nil", err)
	}
	if _, ok := p.(*subtle.HMAC); !ok {
		t.Error("primitive is not of type *subtle.HMAC")
	}
}

func TestPrimitiveFromKeyDataErrors(t *testing.T) {
	registryConfig := &registryconfig.RegistryConfig{}

	testCases := []struct {
		name    string
		keyData *tinkpb.KeyData
	}{
		{
			name: "unregistered url",
			keyData: func() *tinkpb.KeyData {
				kd := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
				kd.TypeUrl = "some url"
				return kd
			}(),
		},
		{
			name: "mismatching url",
			keyData: func() *tinkpb.KeyData {
				kd := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
				kd.TypeUrl = testutil.AESGCMTypeURL
				return kd
			}(),
		},
		{
			name:    "nil KeyData",
			keyData: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := registryConfig.PrimitiveFromKeyData(tc.keyData, internalapi.Token{}); err == nil {
				t.Errorf("registryConfig.Primitive() err = nil, want not-nil")
			}
		})
	}
}

type testPrimitive struct{}
type testKeyManager struct{}

func (km *testKeyManager) Primitive(_ []byte) (any, error)              { return &testPrimitive{}, nil }
func (km *testKeyManager) NewKey(_ []byte) (proto.Message, error)       { return nil, nil }
func (km *testKeyManager) DoesSupport(typeURL string) bool              { return typeURL == "testKeyManager" }
func (km *testKeyManager) TypeURL() string                              { return "testKeyManager" }
func (km *testKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) { return nil, nil }

func TestRegisterKeyManager(t *testing.T) {
	registryConfig := &registryconfig.RegistryConfig{}
	if err := registryConfig.RegisterKeyManager(new(testKeyManager), internalapi.Token{}); err != nil {
		t.Fatalf("registryConfig.RegisterKeyManager() err = %v, want nil", err)
	}
	if _, err := registry.GetKeyManager("testKeyManager"); err != nil {
		t.Fatalf("registry.GetKeyManager(\"testKeyManager\") err = %v, want nil", err)
	}
	primitive, err := registry.Primitive(new(testKeyManager).TypeURL(), []byte{0, 1, 2, 3})
	if err != nil {
		t.Fatalf("registry.Primitive() err = %v, want nil", err)
	}
	if _, ok := primitive.(*testPrimitive); !ok {
		t.Error("primitive is not of type *testPrimitive")
	}
}
