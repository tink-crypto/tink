// Copyright 2017 Google Inc.
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
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/signature/signature"
	"github.com/google/tink/go/subtle/ecdsa"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/util/testutil"
	"github.com/google/tink/go/util/util"
	commonpb "github.com/google/tink/proto/common_go_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"math/big"
	"testing"
)

type ecdsaParams struct {
	hashType commonpb.HashType
	curve    commonpb.EllipticCurveType
}

func TestNewEcdsaSignKeyManager(t *testing.T) {
	var km *signature.EcdsaSignKeyManager = signature.NewEcdsaSignKeyManager()
	if km == nil {
		t.Errorf("NewEcdsaSignKeyManager returns nil")
	}
}

func TestEcdsaSignGetPrimitiveBasic(t *testing.T) {
	testParams := genValidEcdsaParams()
	km := signature.NewEcdsaSignKeyManager()
	for i := 0; i < len(testParams); i++ {
		key := testutil.NewEcdsaPrivateKey(testParams[i].hashType, testParams[i].curve)
		tmp, err := km.GetPrimitiveFromKey(key)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
		var _ *ecdsa.EcdsaSign = tmp.(*ecdsa.EcdsaSign)

		serializedKey, _ := proto.Marshal(key)
		tmp, err = km.GetPrimitiveFromSerializedKey(serializedKey)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
		var _ *ecdsa.EcdsaSign = tmp.(*ecdsa.EcdsaSign)
	}
}

func TestEcdsaSignGetPrimitiveWithInvalidInput(t *testing.T) {
	// invalid params
	testParams := genInvalidEcdsaParams()
	km := signature.NewEcdsaSignKeyManager()
	for i := 0; i < len(testParams); i++ {
		key := testutil.NewEcdsaPrivateKey(testParams[i].hashType, testParams[i].curve)
		if _, err := km.GetPrimitiveFromKey(key); err == nil {
			t.Errorf("expect an error in test case %d")
		}
		serializedKey, _ := proto.Marshal(key)
		if _, err := km.GetPrimitiveFromSerializedKey(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d")
		}
	}
	// invalid version
	key := testutil.NewEcdsaPrivateKey(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256)
	key.Version = signature.ECDSA_SIGN_KEY_VERSION + 1
	if _, err := km.GetPrimitiveFromKey(key); err == nil {
		t.Errorf("expect an error when version is invalid")
	}
	// nil input
	if _, err := km.GetPrimitiveFromKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.GetPrimitiveFromSerializedKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.GetPrimitiveFromSerializedKey([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}

func TestEcdsaSignNewKeyBasic(t *testing.T) {
	testParams := genValidEcdsaParams()
	km := signature.NewEcdsaSignKeyManager()
	for i := 0; i < len(testParams); i++ {
		params := util.NewEcdsaParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		format := util.NewEcdsaKeyFormat(params)
		tmp, err := km.NewKeyFromKeyFormat(format)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		var key *ecdsapb.EcdsaPrivateKey = tmp.(*ecdsapb.EcdsaPrivateKey)
		if err := validateEcdsaPrivateKey(key, params); err != nil {
			t.Errorf("invalid private key in test case %d: %s", i, err)
		}

		serializedFormat, _ := proto.Marshal(format)
		tmp, err = km.NewKeyFromSerializedKeyFormat(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		key = tmp.(*ecdsapb.EcdsaPrivateKey)
		if err := validateEcdsaPrivateKey(key, params); err != nil {
			t.Errorf("invalid private key in test case %d: %s", i, err)
		}
	}
}

func TestEcdsaSignNewKeyWithInvalidInput(t *testing.T) {
	km := signature.NewEcdsaSignKeyManager()
	// invalid hash and curve type
	testParams := genInvalidEcdsaParams()
	for i := 0; i < len(testParams); i++ {
		params := util.NewEcdsaParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		format := util.NewEcdsaKeyFormat(params)
		if _, err := km.NewKeyFromKeyFormat(format); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
		serializedFormat, _ := proto.Marshal(format)
		if _, err := km.NewKeyFromSerializedKeyFormat(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// invalid encoding
	testParams = genValidEcdsaParams()
	for i := 0; i < len(testParams); i++ {
		params := util.NewEcdsaParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_UNKNOWN_ENCODING)
		format := util.NewEcdsaKeyFormat(params)
		if _, err := km.NewKeyFromKeyFormat(format); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
		serializedFormat, _ := proto.Marshal(format)
		if _, err := km.NewKeyFromSerializedKeyFormat(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil input
	if _, err := km.NewKeyFromKeyFormat(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.NewKeyFromSerializedKeyFormat(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.NewKeyFromSerializedKeyFormat([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}

func TestEcdsaSignNewKeyMultipleTimes(t *testing.T) {
	km := signature.NewEcdsaSignKeyManager()
	testParams := genValidEcdsaParams()
	nTest := 27
	for i := 0; i < len(testParams); i++ {
		keys := make(map[string]bool)
		params := util.NewEcdsaParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		format := util.NewEcdsaKeyFormat(params)
		serializedFormat, _ := proto.Marshal(format)
		for j := 0; j < nTest; j++ {
			key, _ := km.NewKeyFromKeyFormat(format)
			serializedKey, _ := proto.Marshal(key)
			keys[string(serializedKey)] = true

			key, _ = km.NewKeyFromSerializedKeyFormat(serializedFormat)
			serializedKey, _ = proto.Marshal(key)
			keys[string(serializedKey)] = true

			keyData, _ := km.NewKeyData(serializedFormat)
			serializedKey = keyData.Value
			keys[string(serializedKey)] = true
		}
		if len(keys) != nTest*3 {
			t.Errorf("key is repeated with params: %s", params)
		}
	}
}

func TestEcdsaSignNewKeyDataBasic(t *testing.T) {
	km := signature.NewEcdsaSignKeyManager()
	testParams := genValidEcdsaParams()
	for i := 0; i < len(testParams); i++ {
		params := util.NewEcdsaParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		format := util.NewEcdsaKeyFormat(params)
		serializedFormat, _ := proto.Marshal(format)

		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case  %d: %s", i, err)
		}
		if keyData.TypeUrl != signature.ECDSA_SIGN_TYPE_URL {
			t.Errorf("incorrect type url in test case  %d: expect %s, got %s",
				i, signature.ECDSA_SIGN_TYPE_URL, keyData.TypeUrl)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
			t.Errorf("incorrect key material type in test case  %d: expect %s, got %s",
				i, tinkpb.KeyData_ASYMMETRIC_PRIVATE, keyData.KeyMaterialType)
		}
		key := new(ecdsapb.EcdsaPrivateKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("unexpect error in test case %d: %s", i, err)
		}
		if err := validateEcdsaPrivateKey(key, params); err != nil {
			t.Errorf("invalid private key in test case %d: %s", i, err)
		}
	}
}

func TestEcdsaSignNewKeyDataWithInvalidInput(t *testing.T) {
	km := signature.NewEcdsaSignKeyManager()
	testParams := genInvalidEcdsaParams()
	for i := 0; i < len(testParams); i++ {
		params := util.NewEcdsaParams(testParams[i].hashType, testParams[i].curve,
			ecdsapb.EcdsaSignatureEncoding_DER)
		format := util.NewEcdsaKeyFormat(params)
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

func TestGetPublicKeyDataBasic(t *testing.T) {
	testParams := genValidEcdsaParams()
	km := signature.NewEcdsaSignKeyManager()
	for i := 0; i < len(testParams); i++ {
		key := testutil.NewEcdsaPrivateKey(testParams[i].hashType, testParams[i].curve)
		serializedKey, _ := proto.Marshal(key)

		pubKeyData, err := km.GetPublicKeyData(serializedKey)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
		if pubKeyData.TypeUrl != signature.ECDSA_VERIFY_TYPE_URL {
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

func TestGetPublicKeyDataWithInvalidInput(t *testing.T) {
	km := signature.NewEcdsaSignKeyManager()
	// modified key
	key := testutil.NewEcdsaPrivateKey(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256)
	serializedKey, _ := proto.Marshal(key)
	serializedKey[0] = 0
	if _, err := km.GetPublicKeyData(serializedKey); err == nil {
		t.Errorf("expect an error when input is a modified serialized key")
	}
	// nil
	if _, err := km.GetPublicKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty slice
	if _, err := km.GetPublicKeyData([]byte{}); err == nil {
		t.Errorf("expect an error when input is an empty slice")
	}
}

var errSmallKey = fmt.Errorf("private key doesn't have adequate size")

func validateEcdsaPrivateKey(key *ecdsapb.EcdsaPrivateKey, params *ecdsapb.EcdsaParams) error {
	if key.Version != signature.ECDSA_SIGN_KEY_VERSION {
		return fmt.Errorf("incorrect private key's version: expect %d, got %d",
			signature.ECDSA_SIGN_KEY_VERSION, key.Version)
	}
	publicKey := key.PublicKey
	if publicKey.Version != signature.ECDSA_SIGN_KEY_VERSION {
		return fmt.Errorf("incorrect public key's version: expect %d, got %d",
			signature.ECDSA_SIGN_KEY_VERSION, key.Version)
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
	hash, curve, encoding := util.GetEcdsaParamNames(publicKey.Params)
	signer, err := ecdsa.NewEcdsaSign(hash, curve, encoding, key.KeyValue)
	if err != nil {
		return fmt.Errorf("unexpected error when creating EcdsaSign: %s", err)
	}
	verifier, err := ecdsa.NewEcdsaVerify(hash, curve, encoding, publicKey.X, publicKey.Y)
	if err != nil {
		return fmt.Errorf("unexpected error when creating EcdsaVerify: %s", err)
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

func genValidEcdsaParams() []ecdsaParams {
	return []ecdsaParams{
		ecdsaParams{
			hashType: commonpb.HashType_SHA256,
			curve:    commonpb.EllipticCurveType_NIST_P256,
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

func genInvalidEcdsaParams() []ecdsaParams {
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
