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

package keyderivation

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	prfderpb "github.com/google/tink/go/proto/prf_based_deriver_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	prfBasedDeriverKeyVersion = 0
	prfBasedDeriverTypeURL    = "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"
)

var (
	errInvalidPRFBasedDeriverKey       = errors.New("prf_based_deriver_key_manager: invalid key")
	errInvalidPRFBasedDeriverKeyFormat = errors.New("prf_based_deriver_key_manager: invalid key format")
)

type prfBasedDeriverKeyManager struct{}

var _ registry.KeyManager = (*prfBasedDeriverKeyManager)(nil)

func (km *prfBasedDeriverKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidPRFBasedDeriverKey
	}
	key := &prfderpb.PrfBasedDeriverKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidPRFBasedDeriverKey
	}
	if keyset.ValidateKeyVersion(key.GetVersion(), prfBasedDeriverKeyVersion) != nil {
		return nil, errInvalidPRFBasedDeriverKey
	}
	return newPRFBasedDeriver(key.GetPrfKey(), key.GetParams().GetDerivedKeyTemplate())
}

func (km *prfBasedDeriverKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidPRFBasedDeriverKeyFormat
	}
	keyFormat := &prfderpb.PrfBasedDeriverKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidPRFBasedDeriverKeyFormat
	}
	if keyFormat.GetParams() == nil {
		return nil, errors.New("prf_based_deriver_key_manager: nil PRF-Based Deriver params")
	}
	prfKey, err := registry.NewKeyData(keyFormat.GetPrfKeyTemplate())
	if err != nil {
		return nil, errors.New("prf_based_deriver_key_manager: failed to generate key from PRF key template")
	}
	// Validate PRF key data and derived key template.
	if _, err := newPRFBasedDeriver(prfKey, keyFormat.GetParams().GetDerivedKeyTemplate()); err != nil {
		return nil, fmt.Errorf("prf_based_deriver_key_manager: %v", err)
	}
	return &prfderpb.PrfBasedDeriverKey{
		Version: prfBasedDeriverKeyVersion,
		PrfKey:  prfKey,
		Params:  keyFormat.GetParams(),
	}, nil
}

func (km *prfBasedDeriverKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidPRFBasedDeriverKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         prfBasedDeriverTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

func (km *prfBasedDeriverKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == prfBasedDeriverTypeURL
}

func (km *prfBasedDeriverKeyManager) TypeURL() string {
	return prfBasedDeriverTypeURL
}
