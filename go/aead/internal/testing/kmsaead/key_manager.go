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

// Package kmsaead provides a keymanager for KmsAeadKey that may only be used in tests.
//
// Golang currently doesn't implement KmsAeadKey. This is an internal implementation
// to be used by the cross-language tests.
package kmsaead

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	kmsaeadpb "github.com/google/tink/go/proto/kms_aead_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const kmsAEADTypeURL = "type.googleapis.com/google.crypto.tink.KmsAeadKey"

type keyManager struct{}

func (km *keyManager) Primitive(protoSerializedKey []byte) (any, error) {
	if len(protoSerializedKey) == 0 {
		return nil, errors.New("kmsaead.keyManager: invalid key")
	}
	key := new(kmsaeadpb.KmsAeadKey)
	if err := proto.Unmarshal(protoSerializedKey, key); err != nil {
		return nil, errors.New("kmsaead.keyManager: invalid key")
	}
	err := keyset.ValidateKeyVersion(key.Version, 0)
	if err != nil {
		return nil, errors.New("kmsaead.keyManager: invalid version")
	}
	uri := key.GetParams().GetKeyUri()
	kmsClient, err := registry.GetKMSClient(uri)
	if err != nil {
		return nil, err
	}
	return kmsClient.GetAEAD(uri)
}

func (km *keyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errors.New("kmsaead.keyManager: invalid key format")
	}
	keyFormat := new(kmsaeadpb.KmsAeadKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errors.New("kmsaead.keyManager: invalid key format")
	}
	return &kmsaeadpb.KmsAeadKey{
		Version: 0,
		Params:  keyFormat,
	}, nil
}

func (km *keyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         kmsAEADTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_REMOTE,
	}, nil
}

func (km *keyManager) DoesSupport(typeURL string) bool {
	return typeURL == kmsAEADTypeURL
}

func (km *keyManager) TypeURL() string {
	return kmsAEADTypeURL
}

// NewKeyManager returns a new KeyManager for the KMS AEAD key type.
func NewKeyManager() registry.KeyManager { return new(keyManager) }

// CreateKeyTemplate creates a new KMS AEAD key template.
func CreateKeyTemplate(uri string) (*tinkpb.KeyTemplate, error) {
	f := &kmsaeadpb.KmsAeadKeyFormat{KeyUri: uri}
	serializedFormat, err := proto.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key format: %s", err)
	}
	return &tinkpb.KeyTemplate{
		Value:            serializedFormat,
		TypeUrl:          kmsAEADTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}, nil
}
