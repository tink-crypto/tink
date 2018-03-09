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

package tink

import (
	"fmt"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

var errKeysetHandleInvalidKeyset = fmt.Errorf("keyset_handle: invalid keyset")

// KeysetHandle provides abstracted access to Keysets, to limit the exposure
// of actual protocol buffers that hold sensitive key material.
type KeysetHandle struct {
	keyset          *tinkpb.Keyset
	encryptedKeyset *tinkpb.EncryptedKeyset
}

// newKeysetHandle creates a new instance of KeysetHandle using the given keyset
// and encrypted keyset. The given keyset must not be nil. Otherwise, an error will
// be returned.
func newKeysetHandle(keyset *tinkpb.Keyset,
	encryptedKeyset *tinkpb.EncryptedKeyset) (*KeysetHandle, error) {
	if keyset == nil || len(keyset.Key) == 0 {
		return nil, errKeysetHandleInvalidKeyset
	}
	return &KeysetHandle{
		keyset:          keyset,
		encryptedKeyset: encryptedKeyset,
	}, nil
}

// GetPublicKeysetHandle returns a KeysetHandle of the public keys if the managed
// keyset contains private keys.
func (h *KeysetHandle) GetPublicKeysetHandle() (*KeysetHandle, error) {
	privKeys := h.keyset.Key
	pubKeys := make([]*tinkpb.Keyset_Key, len(privKeys))

	for i := 0; i < len(privKeys); i++ {
		if privKeys[i] == nil || privKeys[i].KeyData == nil {
			return nil, errKeysetHandleInvalidKeyset
		}
		privKeyData := privKeys[i].KeyData
		if privKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
			return nil, fmt.Errorf("keyset_handle: keyset contains a non-private key")
		}
		pubKeyData, err := Registry().GetPublicKeyData(privKeyData.TypeUrl, privKeyData.Value)
		if err != nil {
			return nil, fmt.Errorf("keyset_handle: %s", err)
		}
		if err := h.validateKeyData(pubKeyData); err != nil {
			return nil, fmt.Errorf("keyset_handle: %s", err)
		}
		pubKeys[i] = &tinkpb.Keyset_Key{
			KeyData:          pubKeyData,
			Status:           privKeys[i].Status,
			KeyId:            privKeys[i].KeyId,
			OutputPrefixType: privKeys[i].OutputPrefixType,
		}
	}
	pubKeyset := &tinkpb.Keyset{
		PrimaryKeyId: h.keyset.PrimaryKeyId,
		Key:          pubKeys,
	}
	return newKeysetHandle(pubKeyset, nil)
}

// Keyset returns the Keyset component of this handle.
func (h *KeysetHandle) Keyset() *tinkpb.Keyset {
	return h.keyset
}

// EncryptedKeyset returns the EncryptedKeyset component of this handle.
func (h *KeysetHandle) EncryptedKeyset() *tinkpb.EncryptedKeyset {
	return h.encryptedKeyset
}

// KeysetInfo returns a KeysetInfo of the Keyset of this handle.
// KeysetInfo doesn't contain actual key material.
func (h *KeysetHandle) KeysetInfo() (*tinkpb.KeysetInfo, error) {
	return GetKeysetInfo(h.keyset)
}

// String returns the string representation of the KeysetInfo.
func (h *KeysetHandle) String() string {
	info, err := h.KeysetInfo()
	if err != nil {
		return ""
	}
	return info.String()
}

func (h *KeysetHandle) validateKeyData(keyData *tinkpb.KeyData) error {
	_, err := Registry().GetPrimitiveFromKeyData(keyData)
	return err
}
