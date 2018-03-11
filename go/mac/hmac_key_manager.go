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

package mac

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/subtle/mac"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	hmacpb "github.com/google/tink/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	// HmacTypeURL is the only type URL that this manager supports.
	HmacTypeURL = "type.googleapis.com/google.crypto.tink.HmacKey"

	// HmacKeyVersion is the maxmimal version of keys that this key manager supports.
	HmacKeyVersion = uint32(0)
)

var errInvalidHmacKey = fmt.Errorf("hmac_key_manager: invalid key")
var errInvalidHmacKeyFormat = fmt.Errorf("hmac_key_manager: invalid key format")

// HmacKeyManager generates new HmacKeys and produces new instances of Hmac.
type HmacKeyManager struct{}

// Assert that HmacKeyManager implements the KeyManager interface.
var _ tink.KeyManager = (*HmacKeyManager)(nil)

// NewHmacKeyManager returns a new HmacKeyManager.
func NewHmacKeyManager() *HmacKeyManager {
	return new(HmacKeyManager)
}

// GetPrimitiveFromSerializedKey constructs a Hmac instance for the given
// serialized HmacKey.
func (km *HmacKeyManager) GetPrimitiveFromSerializedKey(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidHmacKey
	}
	key := new(hmacpb.HmacKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidHmacKey
	}
	return km.GetPrimitiveFromKey(key)
}

// GetPrimitiveFromKey constructs a HMAC instance for the given HmacKey.
func (km *HmacKeyManager) GetPrimitiveFromKey(m proto.Message) (interface{}, error) {
	key, ok := m.(*hmacpb.HmacKey)
	if !ok {
		return nil, errInvalidHmacKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hash := tink.GetHashName(key.Params.Hash)
	hmac, err := mac.NewHmac(hash, key.KeyValue, key.Params.TagSize)
	if err != nil {
		return nil, err
	}
	return hmac, nil
}

// NewKeyFromSerializedKeyFormat generates a new HmacKey according to specification
// in the given serialized HmacKeyFormat.
func (km *HmacKeyManager) NewKeyFromSerializedKeyFormat(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidHmacKeyFormat
	}
	keyFormat := new(hmacpb.HmacKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidHmacKeyFormat
	}
	return km.NewKeyFromKeyFormat(keyFormat)
}

// NewKeyFromKeyFormat generates a new HmacKey according to specification in
// the given HmacKeyFormat.
func (km *HmacKeyManager) NewKeyFromKeyFormat(m proto.Message) (proto.Message, error) {
	keyFormat, ok := m.(*hmacpb.HmacKeyFormat)
	if !ok {
		return nil, errInvalidHmacKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return NewHmacKey(keyFormat.Params, HmacKeyVersion, keyValue), nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized HmacKeyFormat. This should be used solely by the key management API.
func (km *HmacKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKeyFromSerializedKeyFormat(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidHmacKeyFormat
	}
	return tink.NewKeyData(HmacTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC), nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *HmacKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == HmacTypeURL
}

// GetKeyType returns the type URL of keys managed by this KeyManager.
func (km *HmacKeyManager) GetKeyType() string {
	return HmacTypeURL
}

// validateKey validates the given HmacKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *HmacKeyManager) validateKey(key *hmacpb.HmacKey) error {
	err := tink.ValidateVersion(key.Version, HmacKeyVersion)
	if err != nil {
		return fmt.Errorf("hmac_key_manager: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	hash := tink.GetHashName(key.Params.Hash)
	return mac.ValidateHmacParams(hash, keySize, key.Params.TagSize)
}

// validateKeyFormat validates the given HmacKeyFormat
func (km *HmacKeyManager) validateKeyFormat(format *hmacpb.HmacKeyFormat) error {
	if format.Params == nil {
		return fmt.Errorf("null HMAC params")
	}
	hash := tink.GetHashName(format.Params.Hash)
	return mac.ValidateHmacParams(hash, format.KeySize, format.Params.TagSize)
}
