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

// Package testutil provides test utilities.
package testutil

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/tink"
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/proto/common_go_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	hmacpb "github.com/google/tink/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// DummyAeadKeyManager is a dummy implementation of the KeyManager interface.
// It returns DummyAead when GetPrimitive() functions are called.
type DummyAeadKeyManager struct{}

var _ tink.KeyManager = (*DummyAeadKeyManager)(nil)

// GetPrimitiveFromSerializedKey constructs a primitive instance for the key given in
// serializedKey, which must be a serialized key protocol buffer handled by this manager.
func (km *DummyAeadKeyManager) GetPrimitiveFromSerializedKey(serializedKey []byte) (interface{}, error) {
	return new(DummyAead), nil
}

// GetPrimitiveFromKey constructs a primitive instance for the key given in {@code key}.
func (km *DummyAeadKeyManager) GetPrimitiveFromKey(m proto.Message) (interface{}, error) {
	return new(DummyAead), nil
}

// NewKeyFromSerializedKeyFormat Generates a new key according to specification in {@code serializedKeyFormat},
// which must be a serialized key format protocol buffer handled by this manager.
func (km *DummyAeadKeyManager) NewKeyFromSerializedKeyFormat(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}

// NewKeyFromKeyFormat generates a new key according to specification in {@code keyFormat}.
func (km *DummyAeadKeyManager) NewKeyFromKeyFormat(m proto.Message) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}

// NewKeyData generates a new {@code KeyData} according to specification in {@code serializedkeyFormat}.
func (km *DummyAeadKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}

// DoesSupport returns true iff this KeyManager supports key type identified by {@code typeURL}.
func (km *DummyAeadKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == aead.AesGcmTypeURL
}

// GetKeyType returns the type URL.
func (km *DummyAeadKeyManager) GetKeyType() string {
	return aead.AesGcmTypeURL
}

// DummyAead is a dummy implementation of Aead interface.
type DummyAead struct{}

// Encrypt encrypts the plaintext.
func (a *DummyAead) Encrypt(plaintext []byte, additionalData []byte) ([]byte, error) {
	return nil, fmt.Errorf("dummy aead encrypt")
}

// Decrypt decrypts the ciphertext.
func (a *DummyAead) Decrypt(ciphertext []byte, additionalData []byte) ([]byte, error) {
	return nil, fmt.Errorf("dummy aead decrypt")
}

// DummyMac is a dummy implementation of Mac interface.
type DummyMac struct {
	Name string
}

// ComputeMac Computes message authentication code (MAC) for {@code data}.
func (h *DummyMac) ComputeMac(data []byte) ([]byte, error) {
	var m []byte
	m = append(m, data...)
	m = append(m, h.Name...)
	return m, nil
}

// VerifyMac verifies whether {@code mac} is a correct authentication code (MAC) for {@code data}.
func (h *DummyMac) VerifyMac(mac []byte, data []byte) (bool, error) {
	return true, nil
}

// NewTestAesGcmKeyset creates a new Keyset containing an AesGcmKey.
func NewTestAesGcmKeyset(primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyData := NewAesGcmKeyData(16)
	return NewTestKeyset(keyData, primaryOutputPrefixType)
}

// NewTestHmacKeyset creates a new Keyset containing a HmacKey.
func NewTestHmacKeyset(tagSize uint32,
	primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyData := NewHmacKeyData(commonpb.HashType_SHA256, tagSize)
	return NewTestKeyset(keyData, primaryOutputPrefixType)
}

// NewTestKeyset creates a new test Keyset.
func NewTestKeyset(keyData *tinkpb.KeyData,
	primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	primaryKey := tink.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 42, primaryOutputPrefixType)
	rawKey := tink.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 43, tinkpb.OutputPrefixType_RAW)
	legacyKey := tink.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 44, tinkpb.OutputPrefixType_LEGACY)
	tinkKey := tink.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 45, tinkpb.OutputPrefixType_TINK)
	crunchyKey := tink.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 46, tinkpb.OutputPrefixType_CRUNCHY)
	keys := []*tinkpb.Keyset_Key{primaryKey, rawKey, legacyKey, tinkKey, crunchyKey}
	return tink.NewKeyset(primaryKey.KeyId, keys)
}

// NewDummyKey returns a dummy key that doesn't contain actual key material.
func NewDummyKey(keyID int, status tinkpb.KeyStatusType, outputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset_Key {
	return &tinkpb.Keyset_Key{
		KeyData:          new(tinkpb.KeyData),
		Status:           status,
		KeyId:            uint32(keyID),
		OutputPrefixType: outputPrefixType,
	}
}

// NewEcdsaPrivateKey creates an EcdsaPrivateKey with a randomly generated key material.
func NewEcdsaPrivateKey(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *ecdsapb.EcdsaPrivateKey {
	curveName := commonpb.EllipticCurveType_name[int32(curve)]
	priv, _ := ecdsa.GenerateKey(subtle.GetCurve(curveName), rand.Reader)
	params := signature.NewEcdsaParams(hashType,
		curve,
		ecdsapb.EcdsaSignatureEncoding_DER)
	publicKey := signature.NewEcdsaPublicKey(signature.EcdsaVerifyKeyVersion,
		params, priv.X.Bytes(), priv.Y.Bytes())
	return signature.NewEcdsaPrivateKey(signature.EcdsaSignKeyVersion,
		publicKey, priv.D.Bytes())
}

// NewEcdsaPrivateKeyData creates a KeyData containing an EcdsaPrivateKey with a randomly generated key material.
func NewEcdsaPrivateKeyData(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *tinkpb.KeyData {
	key := NewEcdsaPrivateKey(hashType, curve)
	serializedKey, _ := proto.Marshal(key)
	return &tinkpb.KeyData{
		TypeUrl:         signature.EcdsaSignTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
}

// NewEcdsaPublicKey creates an EcdsaPublicKey with the specified parameters.
func NewEcdsaPublicKey(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *ecdsapb.EcdsaPublicKey {
	return NewEcdsaPrivateKey(hashType, curve).PublicKey
}

// NewAesGcmKey creates a randomly generated AesGcmKey.
func NewAesGcmKey(keySize uint32) *gcmpb.AesGcmKey {
	keyValue := random.GetRandomBytes(keySize)
	return aead.NewAesGcmKey(aead.AesGcmKeyVersion, keyValue)
}

// NewAesGcmKeyData creates a KeyData containing a randomly generated AesGcmKey.
func NewAesGcmKeyData(keySize uint32) *tinkpb.KeyData {
	keyValue := random.GetRandomBytes(keySize)
	key := aead.NewAesGcmKey(aead.AesGcmKeyVersion, keyValue)
	serializedKey, _ := proto.Marshal(key)
	return tink.NewKeyData(aead.AesGcmTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC)
}

// NewSerializedAesGcmKey creates a AesGcmKey with randomly generated key material.
func NewSerializedAesGcmKey(keySize uint32) []byte {
	key := NewAesGcmKey(keySize)
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal AesGcmKey: %s", err))
	}
	return serializedKey
}

// NewHmacKey creates a new HmacKey with the specified parameters.
func NewHmacKey(hashType commonpb.HashType, tagSize uint32) *hmacpb.HmacKey {
	params := mac.NewHmacParams(hashType, tagSize)
	keyValue := random.GetRandomBytes(20)
	return mac.NewHmacKey(params, mac.HmacKeyVersion, keyValue)
}

// NewHmacKeyFormat creates a new HmacKeyFormat with the specified parameters.
func NewHmacKeyFormat(hashType commonpb.HashType, tagSize uint32) *hmacpb.HmacKeyFormat {
	params := mac.NewHmacParams(hashType, tagSize)
	keySize := uint32(20)
	return mac.NewHmacKeyFormat(params, keySize)
}

// NewHmacKeysetManager returns a new KeysetManager that contains a HmacKey.
func NewHmacKeysetManager() *tink.KeysetManager {
	macTemplate := mac.HmacSha256Tag128KeyTemplate()
	manager := tink.NewKeysetManager(macTemplate, nil, nil)
	err := manager.Rotate()
	if err != nil {
		panic(fmt.Sprintf("cannot rotate keyset manager: %s", err))
	}
	return manager
}

// NewHmacKeyData returns a new KeyData that contains a HmacKey.
func NewHmacKeyData(hashType commonpb.HashType, tagSize uint32) *tinkpb.KeyData {
	key := NewHmacKey(hashType, tagSize)
	serializedKey, _ := proto.Marshal(key)
	return &tinkpb.KeyData{
		TypeUrl:         mac.HmacTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
}
