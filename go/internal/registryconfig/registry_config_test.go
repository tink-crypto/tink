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
	"github.com/google/tink/go/internal/internalapitoken"
	"github.com/google/tink/go/internal/registryconfig"
	"github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestPrimitiveFromKeyDataMatchesRegistryOnSuccess(t *testing.T) {
	keyData := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
	registryConfig := &registryconfig.RegistryConfig{}
	p, err := registryConfig.PrimitiveFromKeyData(keyData, internalapitoken.InternalAPIToken{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if _, ok := p.(*subtle.HMAC); !ok {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrimitiveFromKeyDataMatchesRegistryOnFailure(t *testing.T) {
	keyDataUnregisteredURL := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
	keyDataUnregisteredURL.TypeUrl = "some url"
	keyDataUnmatchedURL := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
	keyDataUnmatchedURL.TypeUrl = testutil.AESGCMTypeURL
	registryConfig := &registryconfig.RegistryConfig{}
	testCases := []struct {
		kd   *tinkpb.KeyData
		name string
	}{{keyDataUnregisteredURL, "unregistered url"}, {keyDataUnmatchedURL, "mismatching url"}, {nil, "nil KeyData"}}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := registryConfig.PrimitiveFromKeyData(testCase.kd, internalapitoken.InternalAPIToken{}); err == nil {
				t.Errorf("expected an error when requesting primitive with %s", testCase.name)
			}
		})
	}
}

type testKeyManager struct{}
type testPrimitive struct{}

func (km *testKeyManager) Primitive(_ []byte) (any, error) {
	return testPrimitive{}, nil
}

func (km *testKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, nil
}

func (km *testKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == "testKeyManager"
}

func (km *testKeyManager) TypeURL() string {
	return "testKeyManager"
}

func (km *testKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, nil
}

func TestRegisterKeyManagerWorks(t *testing.T) {
	registryConfig := &registryconfig.RegistryConfig{}
	err := registryConfig.RegisterKeyManager(new(testKeyManager), internalapitoken.InternalAPIToken{})
	if err != nil {
		t.Fatal("could not register key manager")
	}
	if _, err := registry.GetKeyManager("testKeyManager"); err != nil {
		t.Fatal("expect testKeyManager to exist")
	}
	primitive, err := registry.Primitive(new(testKeyManager).TypeURL(), []byte{0, 1, 2, 3})
	if err != nil {
		t.Fatalf("could not create primitive: %v", err)
	}
	if _, ok := primitive.(testPrimitive); !ok {
		t.Errorf("primitive creation returned incorrect type object: %v", err)
	}
}
