// Copyright 2018 Google LLC
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

// Package testutil provides common methods needed in test code.
package testutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"

	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	subtledaead "github.com/google/tink/go/daead/subtle"
	subtlehybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/tink"

	cmacpb "github.com/google/tink/go/proto/aes_cmac_go_proto"
	aescmacprfpb "github.com/google/tink/go/proto/aes_cmac_prf_go_proto"
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_streaming_go_proto"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	gcmhkdfpb "github.com/google/tink/go/proto/aes_gcm_hkdf_streaming_go_proto"
	gcmsivpb "github.com/google/tink/go/proto/aes_gcm_siv_go_proto"
	aspb "github.com/google/tink/go/proto/aes_siv_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	eciespb "github.com/google/tink/go/proto/ecies_aead_hkdf_go_proto"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	hkdfprfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	hmacprfpb "github.com/google/tink/go/proto/hmac_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
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

// DummyAEAD is a dummy implementation of AEAD interface. It "encrypts" data
// with a simple serialization capturing the dummy name, plaintext, and
// associated data, and "decrypts" it by reversing this and checking that the
// name and associated data match.
type DummyAEAD struct {
	Name string
}

type dummyAEADData struct {
	Name           string
	Plaintext      []byte
	AssociatedData []byte
}

// Encrypt encrypts the plaintext.
func (a *DummyAEAD) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)
	err := encoder.Encode(dummyAEADData{
		Name:           a.Name,
		Plaintext:      plaintext,
		AssociatedData: associatedData,
	})
	if err != nil {
		return nil, fmt.Errorf("dummy aead encrypt: %v", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts the ciphertext.
func (a *DummyAEAD) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	data := dummyAEADData{}
	decoder := gob.NewDecoder(bytes.NewBuffer(ciphertext))
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("dummy aead decrypt: invalid data: %v", err)
	}
	if data.Name != a.Name || !bytes.Equal(data.AssociatedData, associatedData) {
		return nil, errors.New("dummy aead encrypt: name/associated data mismatch")
	}
	return data.Plaintext, nil
}

// AlwaysFailingAead fails encryption and decryption operations.
type AlwaysFailingAead struct {
	Error error
}

var _ (tink.AEAD) = (*AlwaysFailingAead)(nil)

// NewAlwaysFailingAead creates a new always failing AEAD.
func NewAlwaysFailingAead(err error) tink.AEAD {
	return &AlwaysFailingAead{Error: err}
}

// Encrypt returns an error on encryption.
func (a *AlwaysFailingAead) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	return nil, fmt.Errorf("AlwaysFailingAead will always fail on encryption: %v", a.Error)
}

// Decrypt returns an error on decryption.
func (a *AlwaysFailingAead) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	return nil, fmt.Errorf("AlwaysFailingAead will always fail on decryption: %v", a.Error)
}

// TestKeyManager is key manager which can be setup to return an arbitrary primitive for a type URL
// useful for testing.
type TestKeyManager struct {
	primitive interface{}
	typeURL   string
}

var _ registry.KeyManager = (*TestKeyManager)(nil)

// NewTestKeyManager creates a new key manager that returns a specific primitive for a typeURL.
func NewTestKeyManager(primitive interface{}, typeURL string) registry.KeyManager {
	return &TestKeyManager{
		primitive: primitive,
		typeURL:   typeURL,
	}
}

// Primitive constructs a primitive instance for the key given input key.
func (km *TestKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	return km.primitive, nil
}

// NewKey generates a new key according to specification in serializedKeyFormat.
func (km *TestKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, fmt.Errorf("TestKeyManager: not implemented")
}

// NewKeyData generates a new KeyData according to specification in serializedkeyFormat.
func (km *TestKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("TestKeyManager: not implemented")
}

// DoesSupport returns true if this KeyManager supports key type identified by typeURL.
func (km *TestKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == km.typeURL
}

// TypeURL returns the type URL.
func (km *TestKeyManager) TypeURL() string {
	return km.typeURL
}

// DummySigner is a dummy implementation of the Signer interface.
type DummySigner struct {
	aead DummyAEAD
}

// NewDummySigner creates a new dummy signer with the specified name. The name
// is used to pair with the DummyVerifier.
func NewDummySigner(name string) *DummySigner {
	return &DummySigner{DummyAEAD{Name: "dummy public key:" + name}}
}

// Sign signs data.
func (s *DummySigner) Sign(data []byte) ([]byte, error) {
	return s.aead.Encrypt(nil, data)
}

// DummyVerifier is a dummy implementation of the Signer interface.
type DummyVerifier struct {
	aead DummyAEAD
}

// Verify verifies data.
func (v *DummyVerifier) Verify(sig, data []byte) error {
	_, err := v.aead.Decrypt(sig, data)
	return err
}

// NewDummyVerifier creates a new dummy verifier with the specified name. The
// name is used to pair with the DummySigner.
func NewDummyVerifier(name string) *DummyVerifier {
	return &DummyVerifier{DummyAEAD{Name: "dummy public key:" + name}}
}

// DummyMAC is a dummy implementation of Mac interface.
type DummyMAC struct {
	Name string
}

// ComputeMAC computes a message authentication code (MAC) for data.
func (h *DummyMAC) ComputeMAC(data []byte) ([]byte, error) {
	var m []byte
	m = append(m, data...)
	m = append(m, h.Name...)
	return m, nil
}

// VerifyMAC verifies whether mac is a correct message authentication code
// (MAC) for data.
func (h *DummyMAC) VerifyMAC(mac []byte, data []byte) error {
	return nil
}

// DummyKMSClient is a dummy implementation of a KMS Client.
type DummyKMSClient struct{}

var _ registry.KMSClient = (*DummyKMSClient)(nil)

// Supported true if this client does support keyURI
func (d *DummyKMSClient) Supported(keyURI string) bool {
	return keyURI == "dummy"
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

// NewTestAESGCMSIVKeyset creates a new Keyset containing an AESGCMSIVKey.
func NewTestAESGCMSIVKeyset(primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyData := NewAESGCMSIVKeyData(16)
	return NewTestKeyset(keyData, primaryOutputPrefixType)
}

// NewTestAESSIVKeyset creates a new Keyset containing an AesSivKey.
func NewTestAESSIVKeyset(primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyValue := random.GetRandomBytes(subtledaead.AESSIVKeySize)
	key := &aspb.AesSivKey{
		Version:  AESSIVKeyVersion,
		KeyValue: keyValue,
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		log.Fatalf("failed serializing proto: %v", err)
	}
	keyData := NewKeyData(AESSIVTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC)
	return NewTestKeyset(keyData, primaryOutputPrefixType)
}

// NewTestHMACKeyset creates a new Keyset containing a HMACKey.
func NewTestHMACKeyset(tagSize uint32,
	primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyData := NewHMACKeyData(commonpb.HashType_SHA256, tagSize)
	return NewTestKeyset(keyData, primaryOutputPrefixType)
}

// NewTestAESGCMHKDFKeyset creates a new Keyset containing an AESGCMHKDFKey.
func NewTestAESGCMHKDFKeyset() *tinkpb.Keyset {
	const (
		keySize               = 16
		derivedKeySize        = 16
		ciphertextSegmentSize = 4096
	)
	keyData := NewAESGCMHKDFKeyData(keySize, derivedKeySize, commonpb.HashType_SHA256, ciphertextSegmentSize)
	return NewTestKeyset(keyData, tinkpb.OutputPrefixType_RAW)
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

// NewRandomECDSAPrivateKey creates an ECDSAPrivateKey with randomly generated key material.
func NewRandomECDSAPrivateKey(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *ecdsapb.EcdsaPrivateKey {
	curveName := commonpb.EllipticCurveType_name[int32(curve)]
	priv, _ := ecdsa.GenerateKey(subtle.GetCurve(curveName), rand.Reader)
	params := NewECDSAParams(hashType, curve, ecdsapb.EcdsaSignatureEncoding_DER)
	publicKey := NewECDSAPublicKey(ECDSAVerifierKeyVersion, params, priv.X.Bytes(), priv.Y.Bytes())
	return NewECDSAPrivateKey(ECDSASignerKeyVersion, publicKey, priv.D.Bytes())
}

// NewRandomECDSAPublicKey creates an ECDSAPublicKey with randomly generated key material.
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

// NewED25519PrivateKey creates an ED25519PrivateKey with randomly generated key material.
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

// NewED25519PublicKey creates an ED25519PublicKey with randomly generated key material.
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
	serializedKey, err := proto.Marshal(NewAESGCMKey(AESGCMKeyVersion, keySize))
	if err != nil {
		log.Fatalf("failed serializing proto: %v", err)
	}
	return NewKeyData(AESGCMTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC)
}

// NewAESGCMKeyFormat returns a new AESGCMKeyFormat.
func NewAESGCMKeyFormat(keySize uint32) *gcmpb.AesGcmKeyFormat {
	return &gcmpb.AesGcmKeyFormat{
		KeySize: keySize,
	}
}

// NewAESGCMSIVKey creates a randomly generated AESGCMSIVKey.
func NewAESGCMSIVKey(keyVersion uint32, keySize uint32) *gcmsivpb.AesGcmSivKey {
	keyValue := random.GetRandomBytes(keySize)
	return &gcmsivpb.AesGcmSivKey{
		Version:  keyVersion,
		KeyValue: keyValue,
	}
}

// NewAESGCMSIVKeyData creates a KeyData containing a randomly generated AESGCMSIVKey.
func NewAESGCMSIVKeyData(keySize uint32) *tinkpb.KeyData {
	serializedKey, err := proto.Marshal(NewAESGCMSIVKey(AESGCMKeyVersion, keySize))
	if err != nil {
		log.Fatalf("NewAESGCMSIVKeyData(keySize=%d): Failed serializing proto; err=%v", keySize, err)
	}
	return NewKeyData(AESGCMTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC)
}

// NewAESGCMSIVKeyFormat returns a new AESGCMKeyFormat.
func NewAESGCMSIVKeyFormat(keySize uint32) *gcmsivpb.AesGcmSivKeyFormat {
	return &gcmsivpb.AesGcmSivKeyFormat{
		KeySize: keySize,
	}
}

// NewAESGCMHKDFKey creates a randomly generated AESGCMHKDFKey.
func NewAESGCMHKDFKey(
	keyVersion uint32,
	keySize uint32,
	derivedKeySize uint32,
	hkdfHashType commonpb.HashType,
	ciphertextSegmentSize uint32,
) *gcmhkdfpb.AesGcmHkdfStreamingKey {
	keyValue := random.GetRandomBytes(keySize)
	return &gcmhkdfpb.AesGcmHkdfStreamingKey{
		Version:  keyVersion,
		KeyValue: keyValue,
		Params: &gcmhkdfpb.AesGcmHkdfStreamingParams{
			CiphertextSegmentSize: ciphertextSegmentSize,
			DerivedKeySize:        derivedKeySize,
			HkdfHashType:          hkdfHashType,
		},
	}
}

// NewAESGCMHKDFKeyData creates a KeyData containing a randomly generated AESGCMHKDFKey.
func NewAESGCMHKDFKeyData(
	keySize uint32,
	derivedKeySize uint32,
	hkdfHashType commonpb.HashType,
	ciphertextSegmentSize uint32,
) *tinkpb.KeyData {
	serializedKey, err := proto.Marshal(NewAESGCMHKDFKey(AESGCMHKDFKeyVersion, keySize, derivedKeySize, hkdfHashType, ciphertextSegmentSize))
	if err != nil {
		log.Fatalf("failed serializing proto: %v", err)
	}
	return NewKeyData(AESGCMHKDFTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC)
}

// NewAESGCMHKDFKeyFormat returns a new AESGCMHKDFKeyFormat.
func NewAESGCMHKDFKeyFormat(
	keySize uint32,
	derivedKeySize uint32,
	hkdfHashType commonpb.HashType,
	ciphertextSegmentSize uint32,
) *gcmhkdfpb.AesGcmHkdfStreamingKeyFormat {
	return &gcmhkdfpb.AesGcmHkdfStreamingKeyFormat{
		KeySize: keySize,
		Params: &gcmhkdfpb.AesGcmHkdfStreamingParams{
			CiphertextSegmentSize: ciphertextSegmentSize,
			DerivedKeySize:        derivedKeySize,
			HkdfHashType:          hkdfHashType,
		},
	}
}

// NewAESCTRHMACKey creates a randomly generated AESCTRHMACKey.
func NewAESCTRHMACKey(
	keyVersion uint32,
	keySize uint32,
	hkdfHashType commonpb.HashType,
	derivedKeySize uint32,
	hashType commonpb.HashType,
	tagSize uint32,
	ciphertextSegmentSize uint32,
) *ctrhmacpb.AesCtrHmacStreamingKey {
	keyValue := random.GetRandomBytes(keySize)
	return &ctrhmacpb.AesCtrHmacStreamingKey{
		Version:  keyVersion,
		KeyValue: keyValue,
		Params: &ctrhmacpb.AesCtrHmacStreamingParams{
			CiphertextSegmentSize: ciphertextSegmentSize,
			DerivedKeySize:        derivedKeySize,
			HkdfHashType:          hkdfHashType,
			HmacParams: &hmacpb.HmacParams{
				Hash:    hashType,
				TagSize: tagSize,
			},
		},
	}
}

// NewAESCTRHMACKeyFormat returns a new AESCTRHMACKeyFormat.
func NewAESCTRHMACKeyFormat(
	keySize uint32,
	hkdfHashType commonpb.HashType,
	derivedKeySize uint32,
	hashType commonpb.HashType,
	tagSize uint32,
	ciphertextSegmentSize uint32,
) *ctrhmacpb.AesCtrHmacStreamingKeyFormat {
	return &ctrhmacpb.AesCtrHmacStreamingKeyFormat{
		KeySize: keySize,
		Params: &ctrhmacpb.AesCtrHmacStreamingParams{
			CiphertextSegmentSize: ciphertextSegmentSize,
			DerivedKeySize:        derivedKeySize,
			HkdfHashType:          hkdfHashType,
			HmacParams: &hmacpb.HmacParams{
				Hash:    hashType,
				TagSize: tagSize,
			},
		},
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

// NewAESCMACParams returns a new AESCMACParams.
func NewAESCMACParams(tagSize uint32) *cmacpb.AesCmacParams {
	return &cmacpb.AesCmacParams{
		TagSize: tagSize,
	}
}

// NewAESCMACKey creates a new AESCMACKey with the specified parameters.
func NewAESCMACKey(tagSize uint32) *cmacpb.AesCmacKey {
	params := NewAESCMACParams(tagSize)
	keyValue := random.GetRandomBytes(32)
	return &cmacpb.AesCmacKey{
		Version:  AESCMACKeyVersion,
		Params:   params,
		KeyValue: keyValue,
	}
}

// NewAESCMACKeyFormat creates a new AESCMACKeyFormat with the specified parameters.
func NewAESCMACKeyFormat(tagSize uint32) *cmacpb.AesCmacKeyFormat {
	params := NewAESCMACParams(tagSize)
	keySize := uint32(32)
	return &cmacpb.AesCmacKeyFormat{
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
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		log.Fatalf("failed serializing proto: %v", err)
	}
	return &tinkpb.KeyData{
		TypeUrl:         HMACTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
}

// NewHMACPRFParams returns a new HMACPRFParams.
func NewHMACPRFParams(hashType commonpb.HashType) *hmacprfpb.HmacPrfParams {
	return &hmacprfpb.HmacPrfParams{
		Hash: hashType,
	}
}

// NewHMACPRFKey creates a new HMACPRFKey with the specified parameters.
func NewHMACPRFKey(hashType commonpb.HashType) *hmacprfpb.HmacPrfKey {
	params := NewHMACPRFParams(hashType)
	keyValue := random.GetRandomBytes(32)
	return &hmacprfpb.HmacPrfKey{
		Version:  HMACPRFKeyVersion,
		Params:   params,
		KeyValue: keyValue,
	}
}

// NewHMACPRFKeyFormat creates a new HMACPRFKeyFormat with the specified parameters.
func NewHMACPRFKeyFormat(hashType commonpb.HashType) *hmacprfpb.HmacPrfKeyFormat {
	params := NewHMACPRFParams(hashType)
	keySize := uint32(32)
	return &hmacprfpb.HmacPrfKeyFormat{
		Params:  params,
		KeySize: keySize,
	}
}

// NewHKDFPRFParams returns a new HKDFPRFParams.
func NewHKDFPRFParams(hashType commonpb.HashType, salt []byte) *hkdfprfpb.HkdfPrfParams {
	return &hkdfprfpb.HkdfPrfParams{
		Hash: hashType,
		Salt: salt,
	}
}

// NewHKDFPRFKey creates a new HKDFPRFKey with the specified parameters.
func NewHKDFPRFKey(hashType commonpb.HashType, salt []byte) *hkdfprfpb.HkdfPrfKey {
	params := NewHKDFPRFParams(hashType, salt)
	keyValue := random.GetRandomBytes(32)
	return &hkdfprfpb.HkdfPrfKey{
		Version:  HKDFPRFKeyVersion,
		Params:   params,
		KeyValue: keyValue,
	}
}

// NewHKDFPRFKeyFormat creates a new HKDFPRFKeyFormat with the specified parameters.
func NewHKDFPRFKeyFormat(hashType commonpb.HashType, salt []byte) *hkdfprfpb.HkdfPrfKeyFormat {
	params := NewHKDFPRFParams(hashType, salt)
	keySize := uint32(32)
	return &hkdfprfpb.HkdfPrfKeyFormat{
		Params:  params,
		KeySize: keySize,
	}
}

// NewAESCMACPRFKey creates a new AESCMACPRFKey with the specified parameters.
func NewAESCMACPRFKey() *aescmacprfpb.AesCmacPrfKey {
	keyValue := random.GetRandomBytes(32)
	return &aescmacprfpb.AesCmacPrfKey{
		Version:  AESCMACPRFKeyVersion,
		KeyValue: keyValue,
	}
}

// NewAESCMACPRFKeyFormat creates a new AESCMACPRFKeyFormat with the specified parameters.
func NewAESCMACPRFKeyFormat() *aescmacprfpb.AesCmacPrfKeyFormat {
	keySize := uint32(32)
	return &aescmacprfpb.AesCmacPrfKeyFormat{
		KeySize: keySize,
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

// GenerateMutations generates different byte mutations for a given byte array.
func GenerateMutations(src []byte) (all [][]byte) {
	// Flip bits
	for i := 0; i < len(src); i++ {
		for j := 0; j < 8; j++ {
			n := make([]byte, len(src))
			copy(n, src)
			n[i] = n[i] ^ (1 << uint8(j))
			all = append(all, n)
		}
	}

	//truncate bytes
	for i := 1; i < len(src); i++ {
		n := make([]byte, len(src[i:]))
		copy(n, src[i:])
		all = append(all, n)
	}

	//append extra byte
	m := make([]byte, len(src)+1)
	copy(m, src)
	all = append(all, m)
	return
}

// ZTestUniformString uses a z test on the given byte string, expecting all
// bits to be uniformly set with probability 1/2. Returns non ok status if the
// z test fails by more than 10 standard deviations.
//
// With less statistics jargon: This counts the number of bits set and expects
// the number to be roughly half of the length of the string. The law of large
// numbers suggests that we can assume that the longer the string is, the more
// accurate that estimate becomes for a random string. This test is useful to
// detect things like strings that are entirely zero.
//
// Note: By itself, this is a very weak test for randomness.
func ZTestUniformString(bytes []byte) error {
	expected := float64(len(bytes)) * 8.0 / 2.0
	stddev := math.Sqrt(float64(len(bytes)) * 8.0 / 4.0)
	numSetBits := int64(0)
	for _, b := range bytes {
		// Counting the number of bits set in byte:
		for b != 0 {
			numSetBits++
			b = b & (b - 1)
		}
	}
	// Check that the number of bits is within 10 stddevs.
	if math.Abs(float64(numSetBits)-expected) < 10.0*stddev {
		return nil
	}
	return fmt.Errorf("Z test for uniformly distributed variable out of bounds; "+
		"Actual number of set bits was %d expected was %0.00f, 10 * standard deviation is 10 * %0.00f = %0.00f",
		numSetBits, expected, stddev, 10.0*stddev)
}

func rotate(bytes []byte) []byte {
	result := make([]byte, len(bytes))
	for i := 0; i < len(bytes); i++ {
		prev := i
		if i == 0 {
			prev = len(bytes)
		}
		result[i] = (bytes[i] >> 1) |
			(bytes[prev-1] << 7)
	}
	return result
}

// ZTestCrosscorrelationUniformStrings tests that the crosscorrelation of two
// strings of equal length points to independent and uniformly distributed
// strings. Returns non ok status if the z test fails by more than 10 standard
// deviations.
//
// With less statistics jargon: This xors two strings and then performs the
// ZTestUniformString on the result. If the two strings are independent and
// uniformly distributed, the xor'ed string is as well. A cross correlation test
// will find whether two strings overlap more or less than it would be expected.
//
// Note: Having a correlation of zero is only a necessary but not sufficient
// condition for independence.
func ZTestCrosscorrelationUniformStrings(bytes1,
	bytes2 []byte) error {
	if len(bytes1) != len(bytes2) {
		return fmt.Errorf(
			"Strings are not of equal length")
	}
	crossed := make([]byte, len(bytes1))
	for i := 0; i < len(bytes1); i++ {
		crossed[i] = bytes1[i] ^ bytes2[i]
	}
	return ZTestUniformString(crossed)
}

// ZTestAutocorrelationUniformString tests that the autocorrelation of a string
// points to the bits being independent and uniformly distributed.
// Rotates the string in a cyclic fashion. Returns non ok status if the z test
// fails by more than 10 standard deviations.
//
// With less statistics jargon: This rotates the string bit by bit and performs
// ZTestCrosscorrelationUniformStrings on each of the rotated strings and the
// original. This will find self similarity of the input string, especially
// periodic self similarity. For example, it is a decent test to find English
// text (needs about 180 characters with the current settings).
//
// Note: Having a correlation of zero is only a necessary but not sufficient
// condition for independence.
func ZTestAutocorrelationUniformString(bytes []byte) error {
	rotated := make([]byte, len(bytes))
	copy(rotated, bytes)
	violations := []string{}
	for i := 1; i < len(bytes)*8; i++ {
		rotated = rotate(rotated)
		err := ZTestCrosscorrelationUniformStrings(bytes, rotated)
		if err != nil {
			violations = append(violations, strconv.Itoa(i))
		}
	}
	if len(violations) == 0 {
		return nil
	}
	return fmt.Errorf("Autocorrelation exceeded 10 standard deviation at %d indices: %s", len(violations), strings.Join(violations, ", "))
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
