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
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

var errInvalidKeyset = fmt.Errorf("keyset_handle: invalid keyset")

// KeysetHandle provides access to a Keyset protobuf, to limit the exposure of actual protocol
// buffers that hold sensitive key material.
type KeysetHandle struct {
	ks *tinkpb.Keyset
}

// NewKeysetHandle creates a keyset handle that contains a single fresh key generated according
// to the given KeyTemplate.
func NewKeysetHandle(kt *tinkpb.KeyTemplate) (*KeysetHandle, error) {
	ksm := NewKeysetManager()
	err := ksm.Rotate(kt)
	if err != nil {
		return nil, fmt.Errorf("keyset_handle: cannot generate new keyset: %s", err)
	}
	handle, err := ksm.KeysetHandle()
	if err != nil {
		return nil, fmt.Errorf("keyset_handle: cannot get keyset handle: %s", err)
	}
	return handle, nil
}

// NewKeysetHandleFromReader tries to create a KeysetHandle from an encrypted keyset obtained via reader.
func NewKeysetHandleFromReader(reader KeysetReader, masterKey AEAD) (*KeysetHandle, error) {
	encryptedKeyset, err := reader.ReadEncrypted()
	if err != nil {
		return nil, err
	}
	ks, err := decrypt(encryptedKeyset, masterKey)
	if err != nil {
		return nil, err
	}
	return &KeysetHandle{ks}, nil
}

// KeysetHandleWithNoSecret creates a new instance of KeysetHandle using the given keyset which does
// not contain any secret key material.
func KeysetHandleWithNoSecret(ks *tinkpb.Keyset) (*KeysetHandle, error) {
	for i := 0; i < len(ks.Key); i++ {
		if ks.Key[i] == nil || ks.Key[i].KeyData == nil {
			return nil, errInvalidKeyset
		}
		if ks.Key[i].KeyData.KeyMaterialType == tinkpb.KeyData_ASYMMETRIC_PRIVATE || ks.Key[i].KeyData.KeyMaterialType == tinkpb.KeyData_SYMMETRIC {
			return nil, fmt.Errorf("keyset_handle: keyset contains a secret key material")
		}
		if err := validateKeyData(ks.Key[i].KeyData); err != nil {
			return nil, fmt.Errorf("keyset_handle: %s", err)
		}
	}
	return &KeysetHandle{ks}, nil
}

// Public returns a KeysetHandle of the public keys if the managed keyset contains private keys.
func (h *KeysetHandle) Public() (*KeysetHandle, error) {
	privKeys := h.ks.Key
	pubKeys := make([]*tinkpb.Keyset_Key, len(privKeys))

	for i := 0; i < len(privKeys); i++ {
		if privKeys[i] == nil || privKeys[i].KeyData == nil {
			return nil, errInvalidKeyset
		}
		privKeyData := privKeys[i].KeyData
		pubKeyData, err := publicKeyData(privKeyData)
		if err != nil {
			return nil, fmt.Errorf("keyset_handle: %s", err)
		}
		if err := validateKeyData(pubKeyData); err != nil {
			return nil, fmt.Errorf("keyset_handle: %s", err)
		}
		pubKeys[i] = &tinkpb.Keyset_Key{
			KeyData:          pubKeyData,
			Status:           privKeys[i].Status,
			KeyId:            privKeys[i].KeyId,
			OutputPrefixType: privKeys[i].OutputPrefixType,
		}
	}
	ks := &tinkpb.Keyset{
		PrimaryKeyId: h.ks.PrimaryKeyId,
		Key:          pubKeys,
	}
	return &KeysetHandle{ks}, nil
}

// Keyset returns the Keyset managed by this handle.
func (h *KeysetHandle) Keyset() *tinkpb.Keyset {
	return h.ks
}

// String returns a string representation of the managed keyset.
// The result does not contain any sensitive key material.
func (h *KeysetHandle) String() string {
	info, err := getKeysetInfo(h.ks)
	if err != nil {
		return ""
	}
	return info.String()
}

// Write encrypts and writes an encrypted keyset.
func (h *KeysetHandle) Write(writer KeysetWriter, masterKey AEAD) error {
	encrypted, err := encrypt(h.Keyset(), masterKey)
	if err != nil {
		return err
	}
	return writer.WriteEncrypted(encrypted)
}

func publicKeyData(privKeyData *tinkpb.KeyData) (*tinkpb.KeyData, error) {
	if privKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
		return nil, fmt.Errorf("keyset_handle: keyset contains a non-private key")
	}
	km, err := GetKeyManager(privKeyData.TypeUrl)
	if err != nil {
		return nil, err
	}
	pkm, ok := km.(PrivateKeyManager)
	if !ok {
		return nil, fmt.Errorf("keyset_handle: %s does not belong to a PrivateKeyManager", privKeyData.TypeUrl)
	}
	return pkm.PublicKeyData(privKeyData.Value)
}

func validateKeyData(keyData *tinkpb.KeyData) error {
	_, err := PrimitiveFromKeyData(keyData)
	return err
}

func decrypt(encryptedKeyset *tinkpb.EncryptedKeyset, masterKey AEAD) (*tinkpb.Keyset, error) {
	if encryptedKeyset == nil || masterKey == nil {
		return nil, fmt.Errorf("keyset_handle: invalid encrypted keyset")
	}
	decrypted, err := masterKey.Decrypt(encryptedKeyset.EncryptedKeyset, []byte{})
	if err != nil {
		return nil, fmt.Errorf("keyset_handle: decryption failed: %s", err)
	}
	keyset := new(tinkpb.Keyset)
	if err := proto.Unmarshal(decrypted, keyset); err != nil {
		return nil, errInvalidKeyset
	}
	return keyset, nil
}

func encrypt(keyset *tinkpb.Keyset, masterKey AEAD) (*tinkpb.EncryptedKeyset, error) {
	serializedKeyset, err := proto.Marshal(keyset)
	if err != nil {
		return nil, errInvalidKeyset
	}
	encrypted, err := masterKey.Encrypt(serializedKeyset, []byte{})
	if err != nil {
		return nil, fmt.Errorf("keyset_handle: encrypted failed: %s", err)
	}
	// get keyset info
	info, err := getKeysetInfo(keyset)
	if err != nil {
		return nil, fmt.Errorf("keyset_handle: cannot get keyset info: %s", err)
	}
	encryptedKeyset := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encrypted,
		KeysetInfo:      info,
	}
	return encryptedKeyset, nil
}

// getKeysetInfo returns a KeysetInfo from a Keyset protobuf.
func getKeysetInfo(keyset *tinkpb.Keyset) (*tinkpb.KeysetInfo, error) {
	if keyset == nil {
		return nil, errors.New("keyset_handle: keyset must be non nil")
	}
	nKey := len(keyset.Key)
	keyInfos := make([]*tinkpb.KeysetInfo_KeyInfo, nKey)
	for i, key := range keyset.Key {
		info, err := getKeyInfo(key)
		if err != nil {
			return nil, err
		}
		keyInfos[i] = info
	}
	return &tinkpb.KeysetInfo{
		PrimaryKeyId: keyset.PrimaryKeyId,
		KeyInfo:      keyInfos,
	}, nil
}

// getKeyInfo returns a KeyInfo from a Key protobuf.
func getKeyInfo(key *tinkpb.Keyset_Key) (*tinkpb.KeysetInfo_KeyInfo, error) {
	if key == nil {
		return nil, errors.New("keyset_handle: keyset must be non nil")
	}
	return &tinkpb.KeysetInfo_KeyInfo{
		TypeUrl:          key.KeyData.TypeUrl,
		Status:           key.Status,
		KeyId:            key.KeyId,
		OutputPrefixType: key.OutputPrefixType,
	}, nil
}
