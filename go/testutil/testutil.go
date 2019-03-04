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

// Package testutil provides common methods needed in test code.
package testutil

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ed25519"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	subtlehybrid "github.com/google/tink/go/subtle/hybrid"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/tink"

	subtedaead "github.com/google/tink/go/subtle/daead"
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	aspb "github.com/google/tink/proto/aes_siv_go_proto"
	commonpb "github.com/google/tink/proto/common_go_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	eciespb "github.com/google/tink/proto/ecies_aead_hkdf_go_proto"
	ed25519pb "github.com/google/tink/proto/ed25519_go_proto"
	hmacpb "github.com/google/tink/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// DummyAEADKeyManager is a dummy implementation of the KeyManager interface.
// It returns DummyAEAD when GetPrimitive() functions are called.
type DummyAEADKeyManager struct{}

var _ registry.KeyManager = (*DummyAEADKeyManager)(nil)

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
	return typeURL == AESGCMTypeURL
}

// TypeURL returns the type URL.
func (km *DummyAEADKeyManager) TypeURL() string {
	return AESGCMTypeURL
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

// DummyKMSClient is a dummy implementation of a KMS Client.
type DummyKMSClient struct{}

var _ registry.KMSClient = (*DummyKMSClient)(nil)

// Supported true if this client does support keyURI
func (d *DummyKMSClient) Supported(keyURI string) bool {
	if keyURI == "dummy" {
		return true
	}
	return false
}

// LoadCredentials loads the credentials in credentialPath. If credentialPath is null, loads the
// default credentials.
func (d *DummyKMSClient) LoadCredentials(credentialPath string) (interface{}, error) {
	return d, nil
}

// LoadDefaultCredentials loads with the default credentials.
func (d *DummyKMSClient) LoadDefaultCredentials() (interface{}, error) {
	return d, nil
}

// GetAEAD gets an Aead backend by keyURI.
func (d *DummyKMSClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	return &DummyAEAD{}, nil
}

// NewTestAESGCMKeyset creates a new Keyset containing an AESGCMKey.
func NewTestAESGCMKeyset(primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyData := NewAESGCMKeyData(16)
	return NewTestKeyset(keyData, primaryOutputPrefixType)
}

// NewTestAESSIVKeyset creates a new Keyset containing an AesSivKey.
func NewTestAESSIVKeyset(primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyValue := random.GetRandomBytes(subtedaead.AESSIVKeySize)
	key := &aspb.AesSivKey{
		Version:  AESSIVKeyVersion,
		KeyValue: keyValue,
	}
	serializedKey, _ := proto.Marshal(key)
	keyData := NewKeyData(AESSIVTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC)
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
	primaryKey := NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 42, primaryOutputPrefixType)
	rawKey := NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 43, tinkpb.OutputPrefixType_RAW)
	legacyKey := NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 44, tinkpb.OutputPrefixType_LEGACY)
	tinkKey := NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 45, tinkpb.OutputPrefixType_TINK)
	crunchyKey := NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 46, tinkpb.OutputPrefixType_CRUNCHY)
	keys := []*tinkpb.Keyset_Key{primaryKey, rawKey, legacyKey, tinkKey, crunchyKey}
	return NewKeyset(primaryKey.KeyId, keys)
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

// NewECDSAParams creates a ECDSAParams with the specified parameters.
func NewECDSAParams(hashType commonpb.HashType,
	curve commonpb.EllipticCurveType,
	encoding ecdsapb.EcdsaSignatureEncoding) *ecdsapb.EcdsaParams {
	return &ecdsapb.EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}
}

// NewECDSAKeyFormat creates a ECDSAKeyFormat with the specified parameters.
func NewECDSAKeyFormat(params *ecdsapb.EcdsaParams) *ecdsapb.EcdsaKeyFormat {
	return &ecdsapb.EcdsaKeyFormat{Params: params}
}

// NewECDSAPrivateKey creates a ECDSAPrivateKey with the specified paramaters.
func NewECDSAPrivateKey(version uint32,
	publicKey *ecdsapb.EcdsaPublicKey,
	keyValue []byte) *ecdsapb.EcdsaPrivateKey {
	return &ecdsapb.EcdsaPrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}

// NewECDSAPublicKey creates a ECDSAPublicKey with the specified paramaters.
func NewECDSAPublicKey(version uint32,
	params *ecdsapb.EcdsaParams,
	x []byte, y []byte) *ecdsapb.EcdsaPublicKey {
	return &ecdsapb.EcdsaPublicKey{
		Version: version,
		Params:  params,
		X:       x,
		Y:       y,
	}
}

// NewRandomECDSAPrivateKey creates an ECDSAPrivateKey with a randomly generated key material.
func NewRandomECDSAPrivateKey(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *ecdsapb.EcdsaPrivateKey {
	curveName := commonpb.EllipticCurveType_name[int32(curve)]
	priv, _ := ecdsa.GenerateKey(subtle.GetCurve(curveName), rand.Reader)
	params := NewECDSAParams(hashType, curve, ecdsapb.EcdsaSignatureEncoding_DER)
	publicKey := NewECDSAPublicKey(ECDSAVerifierKeyVersion, params, priv.X.Bytes(), priv.Y.Bytes())
	return NewECDSAPrivateKey(ECDSASignerKeyVersion, publicKey, priv.D.Bytes())
}

// NewRandomECDSAPrivateKeyData creates a KeyData containing an ECDSAPrivateKey with a randomly generated key material.
func NewRandomECDSAPrivateKeyData(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *tinkpb.KeyData {
	key := NewRandomECDSAPrivateKey(hashType, curve)
	serializedKey, _ := proto.Marshal(key)
	return &tinkpb.KeyData{
		TypeUrl:         ECDSASignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
}

// NewRandomECDSAPublicKey creates an ECDSAPublicKe with a randomly generated key material.
func NewRandomECDSAPublicKey(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *ecdsapb.EcdsaPublicKey {
	return NewRandomECDSAPrivateKey(hashType, curve).PublicKey
}

// GetECDSAParamNames returns the string representations of each parameter in
// the given ECDSAParams.
func GetECDSAParamNames(params *ecdsapb.EcdsaParams) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.HashType)]
	curveName := commonpb.EllipticCurveType_name[int32(params.Curve)]
	encodingName := ecdsapb.EcdsaSignatureEncoding_name[int32(params.Encoding)]
	return hashName, curveName, encodingName
}

// NewED25519PrivateKey creates an ED25519PrivateKey with a randomly generated key material.
func NewED25519PrivateKey() *ed25519pb.Ed25519PrivateKey {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	publicProto := &ed25519pb.Ed25519PublicKey{
		Version:  ED25519SignerKeyVersion,
		KeyValue: public,
	}
	return &ed25519pb.Ed25519PrivateKey{
		Version:   ED25519SignerKeyVersion,
		PublicKey: publicProto,
		KeyValue:  private.Seed(),
	}
}

// NewED25519PrivateKeyData creates a KeyData containing an ED25519PrivateKey with a randomly generated key material.
func NewED25519PrivateKeyData() *tinkpb.KeyData {
	key := NewED25519PrivateKey()
	serializedKey, _ := proto.Marshal(key)
	return &tinkpb.KeyData{
		TypeUrl:         ED25519SignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
}

// NewED25519PublicKey creates an ED25519PublicKey with a randomly generated key material.
func NewED25519PublicKey() *ed25519pb.Ed25519PublicKey {
	return NewED25519PrivateKey().PublicKey
}

// NewAESGCMKey creates a randomly generated AESGCMKey.
func NewAESGCMKey(keyVersion uint32, keySize uint32) *gcmpb.AesGcmKey {
	keyValue := random.GetRandomBytes(keySize)
	return &gcmpb.AesGcmKey{
		Version:  keyVersion,
		KeyValue: keyValue,
	}
}

// NewAESGCMKeyData creates a KeyData containing a randomly generated AESGCMKey.
func NewAESGCMKeyData(keySize uint32) *tinkpb.KeyData {
	key := NewAESGCMKey(AESGCMKeyVersion, keySize)
	serializedKey, _ := proto.Marshal(key)
	return NewKeyData(AESGCMTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC)
}

// NewSerializedAESGCMKey creates a AESGCMKey with randomly generated key material.
func NewSerializedAESGCMKey(keySize uint32) []byte {
	key := NewAESGCMKey(AESGCMKeyVersion, keySize)
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal AESGCMKey: %s", err))
	}
	return serializedKey
}

// NewAESGCMKeyFormat returns a new AESGCMKeyFormat.
func NewAESGCMKeyFormat(keySize uint32) *gcmpb.AesGcmKeyFormat {
	return &gcmpb.AesGcmKeyFormat{
		KeySize: keySize,
	}
}

// NewHMACParams returns a new HMACParams.
func NewHMACParams(hashType commonpb.HashType, tagSize uint32) *hmacpb.HmacParams {
	return &hmacpb.HmacParams{
		Hash:    hashType,
		TagSize: tagSize,
	}
}

// NewHMACKey creates a new HMACKey with the specified parameters.
func NewHMACKey(hashType commonpb.HashType, tagSize uint32) *hmacpb.HmacKey {
	params := NewHMACParams(hashType, tagSize)
	keyValue := random.GetRandomBytes(20)
	return &hmacpb.HmacKey{
		Version:  HMACKeyVersion,
		Params:   params,
		KeyValue: keyValue,
	}
}

// NewHMACKeyFormat creates a new HMACKeyFormat with the specified parameters.
func NewHMACKeyFormat(hashType commonpb.HashType, tagSize uint32) *hmacpb.HmacKeyFormat {
	params := NewHMACParams(hashType, tagSize)
	keySize := uint32(20)
	return &hmacpb.HmacKeyFormat{
		Params:  params,
		KeySize: keySize,
	}
}

// NewHMACKeysetManager returns a new KeysetManager that contains a HMACKey.
func NewHMACKeysetManager() *keyset.Manager {
	ksm := keyset.NewManager()
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
		TypeUrl:         HMACTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
}

// NewKeyData creates a new KeyData with the specified parameters.
func NewKeyData(typeURL string,
	value []byte,
	materialType tinkpb.KeyData_KeyMaterialType) *tinkpb.KeyData {
	return &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           value,
		KeyMaterialType: materialType,
	}
}

// NewKey creates a new Key with the specified parameters.
func NewKey(keyData *tinkpb.KeyData,
	status tinkpb.KeyStatusType,
	keyID uint32,
	prefixType tinkpb.OutputPrefixType) *tinkpb.Keyset_Key {
	return &tinkpb.Keyset_Key{
		KeyData:          keyData,
		Status:           status,
		KeyId:            keyID,
		OutputPrefixType: prefixType,
	}
}

// NewKeyset creates a new Keyset with the specified parameters.
func NewKeyset(primaryKeyID uint32,
	keys []*tinkpb.Keyset_Key) *tinkpb.Keyset {
	return &tinkpb.Keyset{
		PrimaryKeyId: primaryKeyID,
		Key:          keys,
	}
}

// NewEncryptedKeyset creates a new EncryptedKeyset with a specified parameters.
func NewEncryptedKeyset(encryptedKeySet []byte, info *tinkpb.KeysetInfo) *tinkpb.EncryptedKeyset {
	return &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encryptedKeySet,
		KeysetInfo:      info,
	}
}

// GenerateMutations generates different byte mutations for a given byte array.
func GenerateMutations(src []byte) (all [][]byte) {
	n := make([]byte, len(src))

	// Flip bits
	for i := 0; i < len(src); i++ {
		for j := 0; j < 8; j++ {
			copy(n, src)
			n[i] = n[i] ^ (1 << uint8(j))
			all = append(all, n)
		}
	}

	//truncate bytes
	for i := 0; i < len(src); i++ {
		copy(n, src[i:])
		all = append(all, n)
	}

	//append extra byte
	m := make([]byte, len(src)+1)
	copy(m, src)
	all = append(all, m)
	return
}

// eciesAEADHKDFPublicKey returns a EciesAeadHkdfPublicKey with specified parameters.
func eciesAEADHKDFPublicKey(c commonpb.EllipticCurveType, ht commonpb.HashType, ptfmt commonpb.EcPointFormat, dekT *tinkpb.KeyTemplate, x, y, salt []byte) *eciespb.EciesAeadHkdfPublicKey {
	return &eciespb.EciesAeadHkdfPublicKey{
		Version: 0,
		Params: &eciespb.EciesAeadHkdfParams{
			KemParams: &eciespb.EciesHkdfKemParams{
				CurveType:    c,
				HkdfHashType: ht,
				HkdfSalt:     salt,
			},
			DemParams: &eciespb.EciesAeadDemParams{
				AeadDem: dekT,
			},
			EcPointFormat: ptfmt,
		},
		X: x,
		Y: y,
	}
}

// eciesAEADHKDFPrivateKey returns a EciesAeadHkdfPrivateKey with specified parameters
func eciesAEADHKDFPrivateKey(p *eciespb.EciesAeadHkdfPublicKey, d []byte) *eciespb.EciesAeadHkdfPrivateKey {
	return &eciespb.EciesAeadHkdfPrivateKey{
		Version:   0,
		PublicKey: p,
		KeyValue:  d,
	}
}

// GenerateECIESAEADHKDFPrivateKey generates a new EC key pair and returns the private key proto.
func GenerateECIESAEADHKDFPrivateKey(c commonpb.EllipticCurveType, ht commonpb.HashType, ptfmt commonpb.EcPointFormat, dekT *tinkpb.KeyTemplate, salt []byte) (*eciespb.EciesAeadHkdfPrivateKey, error) {
	curve, err := subtlehybrid.GetCurve(c.String())
	if err != nil {
		return nil, err
	}
	pvt, err := subtlehybrid.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, err
	}
	pubKey := eciesAEADHKDFPublicKey(c, ht, ptfmt, dekT, pvt.PublicKey.Point.X.Bytes(), pvt.PublicKey.Point.Y.Bytes(), salt)
	//fmt.Println(proto.MarshalTextString(pubKey))
	return eciesAEADHKDFPrivateKey(pubKey, pvt.D.Bytes()), nil
}
