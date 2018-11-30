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
	"golang.org/x/crypto/ed25519"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/tink"

	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/proto/common_go_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	ed25519pb "github.com/google/tink/proto/ed25519_go_proto"
	hmacpb "github.com/google/tink/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// DummyAEADKeyManager is a dummy implementation of the KeyManager interface.
// It returns DummyAEAD when GetPrimitive() functions are called.
type DummyAEADKeyManager struct{}

var _ tink.KeyManager = (*DummyAEADKeyManager)(nil)

// Primitive constructs a primitive instance for the key given in
// serializedKey, which must be a serialized key protocol buffer handled by this manager.
func (km *DummyAEADKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	return new(DummyAEAD), nil
}

// NewKey generates a new key according to specification in serializedKeyFormat.
func (km *DummyAEADKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}

// NewKeyData generates a new KeyData according to specification in serializedkeyFormat.
func (km *DummyAEADKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}

// DoesSupport returns true iff this KeyManager supports key type identified by typeURL.
func (km *DummyAEADKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == aead.AESGCMTypeURL
}

// TypeURL returns the type URL.
func (km *DummyAEADKeyManager) TypeURL() string {
	return aead.AESGCMTypeURL
}

// DummyAEAD is a dummy implementation of AEAD interface.
type DummyAEAD struct{}

// Encrypt encrypts the plaintext.
func (a *DummyAEAD) Encrypt(plaintext []byte, additionalData []byte) ([]byte, error) {
	return nil, fmt.Errorf("dummy aead encrypt")
}

// Decrypt decrypts the ciphertext.
func (a *DummyAEAD) Decrypt(ciphertext []byte, additionalData []byte) ([]byte, error) {
	return nil, fmt.Errorf("dummy aead decrypt")
}

// DummyMAC is a dummy implementation of Mac interface.
type DummyMAC struct {
	Name string
}

// ComputeMAC computes message authentication code (MAC) for {@code data}.
func (h *DummyMAC) ComputeMAC(data []byte) ([]byte, error) {
	var m []byte
	m = append(m, data...)
	m = append(m, h.Name...)
	return m, nil
}

// VerifyMAC verifies whether {@code mac} is a correct authentication code (MAC) for {@code data}.
func (h *DummyMAC) VerifyMAC(mac []byte, data []byte) error {
	return nil
}

// NewTestAESGCMKeyset creates a new Keyset containing an AESGCMKey.
func NewTestAESGCMKeyset(primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyData := NewAESGCMKeyData(16)
	return NewTestKeyset(keyData, primaryOutputPrefixType)
}

// NewTestHMACKeyset creates a new Keyset containing a HMACKey.
func NewTestHMACKeyset(tagSize uint32,
	primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyData := NewHMACKeyData(commonpb.HashType_SHA256, tagSize)
	return NewTestKeyset(keyData, primaryOutputPrefixType)
}

// NewTestKeyset creates a new test Keyset.
func NewTestKeyset(keyData *tinkpb.KeyData,
	primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	primaryKey := tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, 42, primaryOutputPrefixType)
	rawKey := tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, 43, tinkpb.OutputPrefixType_RAW)
	legacyKey := tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, 44, tinkpb.OutputPrefixType_LEGACY)
	tinkKey := tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, 45, tinkpb.OutputPrefixType_TINK)
	crunchyKey := tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, 46, tinkpb.OutputPrefixType_CRUNCHY)
	keys := []*tinkpb.Keyset_Key{primaryKey, rawKey, legacyKey, tinkKey, crunchyKey}
	return tink.CreateKeyset(primaryKey.KeyId, keys)
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

// NewECDSAPrivateKey creates an ECDSAPrivateKey with a randomly generated key material.
func NewECDSAPrivateKey(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *ecdsapb.EcdsaPrivateKey {
	curveName := commonpb.EllipticCurveType_name[int32(curve)]
	priv, _ := ecdsa.GenerateKey(subtle.GetCurve(curveName), rand.Reader)
	params := signature.NewECDSAParams(hashType,
		curve,
		ecdsapb.EcdsaSignatureEncoding_DER)
	publicKey := signature.NewECDSAPublicKey(signature.ECDSAVerifierKeyVersion,
		params, priv.X.Bytes(), priv.Y.Bytes())
	return signature.NewECDSAPrivateKey(signature.ECDSASignerKeyVersion,
		publicKey, priv.D.Bytes())
}

// NewECDSAPrivateKeyData creates a KeyData containing an ECDSAPrivateKey with a randomly generated key material.
func NewECDSAPrivateKeyData(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *tinkpb.KeyData {
	key := NewECDSAPrivateKey(hashType, curve)
	serializedKey, _ := proto.Marshal(key)
	return &tinkpb.KeyData{
		TypeUrl:         signature.ECDSASignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
}

// NewECDSAPublicKey creates an ECDSAPublicKey with the specified parameters.
func NewECDSAPublicKey(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *ecdsapb.EcdsaPublicKey {
	return NewECDSAPrivateKey(hashType, curve).PublicKey
}

// NewED25519PrivateKey creates an ED25519PrivateKey with a randomly generated key material.
func NewED25519PrivateKey() *ed25519pb.Ed25519PrivateKey {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	pub := signature.NewED25519PublicKey(signature.ED25519SignerKeyVersion, &public)
	return signature.NewED25519PrivateKey(signature.ED25519SignerKeyVersion,
		pub, &private)
}

// NewED25519PrivateKeyData creates a KeyData containing an ED25519PrivateKey with a randomly generated key material.
func NewED25519PrivateKeyData() *tinkpb.KeyData {
	key := NewED25519PrivateKey()
	serializedKey, _ := proto.Marshal(key)
	return &tinkpb.KeyData{
		TypeUrl:         signature.ED25519SignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
}

// NewED25519PublicKey creates an ED25519PublicKey with the specified parameters.
func NewED25519PublicKey() *ed25519pb.Ed25519PublicKey {
	return NewED25519PrivateKey().PublicKey
}

// NewAESGCMKey creates a randomly generated AESGCMKey.
func NewAESGCMKey(keySize uint32) *gcmpb.AesGcmKey {
	keyValue := random.GetRandomBytes(keySize)
	return aead.NewAESGCMKey(aead.AESGCMKeyVersion, keyValue)
}

// NewAESGCMKeyData creates a KeyData containing a randomly generated AESGCMKey.
func NewAESGCMKeyData(keySize uint32) *tinkpb.KeyData {
	keyValue := random.GetRandomBytes(keySize)
	key := aead.NewAESGCMKey(aead.AESGCMKeyVersion, keyValue)
	serializedKey, _ := proto.Marshal(key)
	return tink.CreateKeyData(aead.AESGCMTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC)
}

// NewSerializedAESGCMKey creates a AESGCMKey with randomly generated key material.
func NewSerializedAESGCMKey(keySize uint32) []byte {
	key := NewAESGCMKey(keySize)
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal AESGCMKey: %s", err))
	}
	return serializedKey
}

// NewHMACKey creates a new HMACKey with the specified parameters.
func NewHMACKey(hashType commonpb.HashType, tagSize uint32) *hmacpb.HmacKey {
	params := mac.NewHMACParams(hashType, tagSize)
	keyValue := random.GetRandomBytes(20)
	return mac.NewHMACKey(params, mac.HMACKeyVersion, keyValue)
}

// NewHMACKeyFormat creates a new HMACKeyFormat with the specified parameters.
func NewHMACKeyFormat(hashType commonpb.HashType, tagSize uint32) *hmacpb.HmacKeyFormat {
	params := mac.NewHMACParams(hashType, tagSize)
	keySize := uint32(20)
	return mac.NewHMACKeyFormat(params, keySize)
}

// NewHMACKeysetManager returns a new KeysetManager that contains a HMACKey.
func NewHMACKeysetManager() *tink.KeysetManager {
	ksm := tink.NewKeysetManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	err := ksm.Rotate(kt)
	if err != nil {
		panic(fmt.Sprintf("cannot rotate keyset manager: %s", err))
	}
	return ksm
}

// NewHMACKeyData returns a new KeyData that contains a HMACKey.
func NewHMACKeyData(hashType commonpb.HashType, tagSize uint32) *tinkpb.KeyData {
	key := NewHMACKey(hashType, tagSize)
	serializedKey, _ := proto.Marshal(key)
	return &tinkpb.KeyData{
		TypeUrl:         mac.HMACTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
}
