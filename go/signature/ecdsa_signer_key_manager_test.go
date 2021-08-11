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

package signature_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

type ecdsaParams struct {
	hashType commonpb.HashType
	curve    commonpb.EllipticCurveType
}

func TestECDSASignerGetPrimitiveBasic(t *testing.T) {
	testParams := genValidECDSAParams()
	km, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ECDSASigner key manager: %s", err)
	}
	for i := 0; i < len(testParams); i++ {
		serializedKey, _ := proto.Marshal(testutil.NewRandomECDSAPrivateKey(testParams[i].hashType, testParams[i].curve))
		_, err := km.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
	}
}

func TestECDSASignGetPrimitiveWithInvalidInput(t *testing.T) {
	// invalid params
	testParams := genInvalidECDSAParams()
	km, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ECDSASigner key manager: %s", err)
	}
	for i := 0; i < len(testParams); i++ {
		serializedKey, _ := proto.Marshal(testutil.NewRandomECDSAPrivateKey(testParams[i].hashType, testParams[i].curve))
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// invalid version
	key := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256)
	key.Version = testutil.ECDSASignerKeyVersion + 1
	serializedKey, _ := proto.Marshal(key)
	if _, err := km.Primitive(serializedKey); err == nil {
		t.Errorf("expect an error when version is invalid")
	}
	// nil input
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}

func TestECDSASignNewKeyBasic(t *testing.T) {
	testParams := genValidECDSAParams()
	km, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ECDSASigner key manager: %s", err)
	}
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		serializedFormat, _ := proto.Marshal(testutil.NewECDSAKeyFormat(params))
		tmp, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		key := tmp.(*ecdsapb.EcdsaPrivateKey)
		if err := validateECDSAPrivateKey(key, params); err != nil {
			t.Errorf("invalid private key in test case %d: %s", i, err)
		}
	}
}

func TestECDSASignNewKeyWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ECDSASigner key manager: %s", err)
	}
	// invalid hash and curve type
	testParams := genInvalidECDSAParams()
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		serializedFormat, _ := proto.Marshal(testutil.NewECDSAKeyFormat(params))
		if _, err := km.NewKey(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// invalid encoding
	testParams = genValidECDSAParams()
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_UNKNOWN_ENCODING)
		serializedFormat, _ := proto.Marshal(testutil.NewECDSAKeyFormat(params))
		if _, err := km.NewKey(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil input
	if _, err := km.NewKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.NewKey([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}

func TestECDSASignNewKeyMultipleTimes(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ECDSASigner key manager: %s", err)
	}
	testParams := genValidECDSAParams()
	nTest := 27
	for i := 0; i < len(testParams); i++ {
		keys := make(map[string]bool)
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		format := testutil.NewECDSAKeyFormat(params)
		serializedFormat, _ := proto.Marshal(format)
		for j := 0; j < nTest; j++ {
			key, _ := km.NewKey(serializedFormat)
			serializedKey, _ := proto.Marshal(key)
			keys[string(serializedKey)] = true

			keyData, _ := km.NewKeyData(serializedFormat)
			serializedKey = keyData.Value
			keys[string(serializedKey)] = true
		}
		if len(keys) != nTest*2 {
			t.Errorf("key is repeated with params: %s", params)
		}
	}
}

func TestECDSASignNewKeyDataBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ECDSASigner key manager: %s", err)
	}
	testParams := genValidECDSAParams()
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		serializedFormat, _ := proto.Marshal(testutil.NewECDSAKeyFormat(params))

		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case  %d: %s", i, err)
		}
		if keyData.TypeUrl != testutil.ECDSASignerTypeURL {
			t.Errorf("incorrect type url in test case  %d: expect %s, got %s",
				i, testutil.ECDSASignerTypeURL, keyData.TypeUrl)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
			t.Errorf("incorrect key material type in test case  %d: expect %s, got %s",
				i, tinkpb.KeyData_ASYMMETRIC_PRIVATE, keyData.KeyMaterialType)
		}
		key := new(ecdsapb.EcdsaPrivateKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("unexpect error in test case %d: %s", i, err)
		}
		if err := validateECDSAPrivateKey(key, params); err != nil {
			t.Errorf("invalid private key in test case %d: %s", i, err)
		}
	}
}

func TestECDSASignNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ECDSASigner key manager: %s", err)
	}
	testParams := genInvalidECDSAParams()
	for i := 0; i < len(testParams); i++ {
		params := testutil.NewECDSAParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		format := testutil.NewECDSAKeyFormat(params)
		serializedFormat, _ := proto.Marshal(format)

		if _, err := km.NewKeyData(serializedFormat); err == nil {
			t.Errorf("expect an error in test case  %d", i)
		}
	}
	// nil input
	if _, err := km.NewKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
}

func TestPublicKeyDataBasic(t *testing.T) {
	testParams := genValidECDSAParams()
	km, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ECDSASigner key manager: %s", err)
	}
	pkm, ok := km.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("cannot obtain private key manager")
	}
	for i := 0; i < len(testParams); i++ {
		key := testutil.NewRandomECDSAPrivateKey(testParams[i].hashType, testParams[i].curve)
		serializedKey, _ := proto.Marshal(key)

		pubKeyData, err := pkm.PublicKeyData(serializedKey)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
		if pubKeyData.TypeUrl != testutil.ECDSAVerifierTypeURL {
			t.Errorf("incorrect type url: %s", pubKeyData.TypeUrl)
		}
		if pubKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
			t.Errorf("incorrect key material type: %d", pubKeyData.KeyMaterialType)
		}
		pubKey := new(ecdsapb.EcdsaPublicKey)
		if err = proto.Unmarshal(pubKeyData.Value, pubKey); err != nil {
			t.Errorf("invalid public key: %s", err)
		}
	}
}

func TestPublicKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ECDSASigner key manager: %s", err)
	}
	pkm, ok := km.(registry.PrivateKeyManager)
	if !ok {
		t.Errorf("cannot obtain private key manager")
	}
	// modified key
	key := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256)
	serializedKey, _ := proto.Marshal(key)
	serializedKey[0] = 0
	if _, err := pkm.PublicKeyData(serializedKey); err == nil {
		t.Errorf("expect an error when input is a modified serialized key")
	}
	// invalid with a single byte
	if _, err := pkm.PublicKeyData([]byte{42}); err == nil {
		t.Errorf("expect an error when input is an empty slice")
	}
}

var errSmallKey = fmt.Errorf("private key doesn't have adequate size")

func validateECDSAPrivateKey(key *ecdsapb.EcdsaPrivateKey, params *ecdsapb.EcdsaParams) error {
	if key.Version != testutil.ECDSASignerKeyVersion {
		return fmt.Errorf("incorrect private key's version: expect %d, got %d",
			testutil.ECDSASignerKeyVersion, key.Version)
	}
	publicKey := key.PublicKey
	if publicKey.Version != testutil.ECDSASignerKeyVersion {
		return fmt.Errorf("incorrect public key's version: expect %d, got %d",
			testutil.ECDSASignerKeyVersion, key.Version)
	}
	if params.HashType != publicKey.Params.HashType ||
		params.Curve != publicKey.Params.Curve ||
		params.Encoding != publicKey.Params.Encoding {
		return fmt.Errorf("incorrect params: expect %s, got %s", params, publicKey.Params)
	}
	if len(publicKey.X) == 0 || len(publicKey.Y) == 0 {
		return fmt.Errorf("public points are not initialized")
	}
	// check private key's size
	d := new(big.Int).SetBytes(key.KeyValue)
	keySize := len(d.Bytes())
	switch params.Curve {
	case commonpb.EllipticCurveType_NIST_P256:
		if keySize < 256/8-8 || keySize > 256/8+1 {
			return errSmallKey
		}
	case commonpb.EllipticCurveType_NIST_P384:
		if keySize < 384/8-8 || keySize > 384/8+1 {
			return errSmallKey
		}
	case commonpb.EllipticCurveType_NIST_P521:
		if keySize < 521/8-8 || keySize > 521/8+1 {
			return errSmallKey
		}
	}
	// try to sign and verify with the key
	hash, curve, encoding := testutil.GetECDSAParamNames(publicKey.Params)
	signer, err := subtle.NewECDSASigner(hash, curve, encoding, key.KeyValue)
	if err != nil {
		return fmt.Errorf("unexpected error when creating ECDSASign: %s", err)
	}
	verifier, err := subtle.NewECDSAVerifier(hash, curve, encoding, publicKey.X, publicKey.Y)
	if err != nil {
		return fmt.Errorf("unexpected error when creating ECDSAVerify: %s", err)
	}
	data := random.GetRandomBytes(1281)
	signature, err := signer.Sign(data)
	if err != nil {
		return fmt.Errorf("unexpected error when signing: %s", err)
	}

	if err := verifier.Verify(signature, data); err != nil {
		return fmt.Errorf("unexpected error when verifying signature: %s", err)
	}
	return nil
}

func genValidECDSAParams() []ecdsaParams {
	return []ecdsaParams{
		ecdsaParams{
			hashType: commonpb.HashType_SHA256,
			curve:    commonpb.EllipticCurveType_NIST_P256,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA384,
			curve:    commonpb.EllipticCurveType_NIST_P384,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA512,
			curve:    commonpb.EllipticCurveType_NIST_P384,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA512,
			curve:    commonpb.EllipticCurveType_NIST_P521,
		},
	}
}

func genInvalidECDSAParams() []ecdsaParams {
	return []ecdsaParams{
		ecdsaParams{
			hashType: commonpb.HashType_SHA1,
			curve:    commonpb.EllipticCurveType_NIST_P256,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA1,
			curve:    commonpb.EllipticCurveType_NIST_P384,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA1,
			curve:    commonpb.EllipticCurveType_NIST_P521,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA256,
			curve:    commonpb.EllipticCurveType_NIST_P384,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA256,
			curve:    commonpb.EllipticCurveType_NIST_P521,
		},
		ecdsaParams{
			hashType: commonpb.HashType_SHA512,
			curve:    commonpb.EllipticCurveType_NIST_P256,
		},
	}
}
