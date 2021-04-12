// Copyright 2020 Google LLC
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

package prf_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/prf/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	cmacpb "github.com/google/tink/go/proto/aes_cmac_prf_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestGetPrimitiveCMACBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("AES CMAC PRF key manager not found: %s", err)
	}
	testKeys := genValidCMACKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, _ := proto.Marshal(testKeys[i])
		p, err := km.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateCMACPrimitive(p, testKeys[i]); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestGetPrimitiveCMACWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES CMAC PRF key manager: %s", err)
	}
	// invalid key
	testKeys := genInvalidCMACKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, _ := proto.Marshal(testKeys[i])
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty input
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestNewKeyCMACMultipleTimes(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES CMAC PRF key manager: %s", err)
	}
	serializedFormat, _ := proto.Marshal(testutil.NewAESCMACPRFKeyFormat())
	keys := make(map[string]bool)
	nTest := 26
	for i := 0; i < nTest; i++ {
		key, _ := km.NewKey(serializedFormat)
		serializedKey, _ := proto.Marshal(key)
		keys[string(serializedKey)] = true

		keyData, _ := km.NewKeyData(serializedFormat)
		serializedKey = keyData.Value
		keys[string(serializedKey)] = true
	}
	if len(keys) != nTest*2 {
		t.Errorf("key is repeated")
	}
}

func TestNewKeyCMACBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES CMAC PRF key manager: %s", err)
	}
	testFormats := genValidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateCMACKey(testFormats[i], key.(*cmacpb.AesCmacPrfKey)); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestNewKeyCMACWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES CMAC PRF key manager: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			fmt.Println("Error!")
		}
		if _, err := km.NewKey(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d: %s", i, err)
		}
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty input
	if _, err := km.NewKey([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestNewKeyDataCMACBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES CMAC PRF key manager: %s", err)
	}
	testFormats := genValidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if keyData.TypeUrl != testutil.AESCMACPRFTypeURL {
			t.Errorf("incorrect type url in test case %d", i)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type in test case %d", i)
		}
		key := new(cmacpb.AesCmacPrfKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("invalid key value")
		}
		if err := validateCMACKey(testFormats[i], key); err != nil {
			t.Errorf("invalid key")
		}
	}
}

func TestNewKeyDataCMACWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("AES CMAC PRF key manager not found: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		if _, err := km.NewKeyData(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil input
	if _, err := km.NewKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
}

func TestCMACDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("AES CMAC PRF key manager not found: %s", err)
	}
	if !km.DoesSupport(testutil.AESCMACPRFTypeURL) {
		t.Errorf("AESCMACPRFKeyManager must support %s", testutil.AESCMACPRFTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("AESCMACPRFKeyManager must support only %s", testutil.AESCMACPRFTypeURL)
	}
}

func TestCMACTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("AES CMAC PRF key manager not found: %s", err)
	}
	if km.TypeURL() != testutil.AESCMACPRFTypeURL {
		t.Errorf("incorrect GetKeyType()")
	}
}

func genInvalidCMACKeys() []proto.Message {
	badVersionKey := testutil.NewAESCMACPRFKey()
	badVersionKey.Version++
	shortKey := testutil.NewAESCMACPRFKey()
	shortKey.KeyValue = []byte{1, 1}
	return []proto.Message{
		// not a AESCMACPRFKey
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// bad version
		badVersionKey,
		// key too short
		shortKey,
	}
}

func genInvalidCMACKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewAESCMACPRFKeyFormat()
	shortKeyFormat.KeySize = 1
	return []proto.Message{
		// not a AESCMACPRFKeyFormat
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// key too short
		shortKeyFormat,
	}
}

func genValidCMACKeyFormats() []*cmacpb.AesCmacPrfKeyFormat {
	return []*cmacpb.AesCmacPrfKeyFormat{
		testutil.NewAESCMACPRFKeyFormat(),
	}
}

func genValidCMACKeys() []*cmacpb.AesCmacPrfKey {
	return []*cmacpb.AesCmacPrfKey{
		testutil.NewAESCMACPRFKey(),
	}
}

// Checks whether the given CMACPRFKey matches the given key AESCMACPRFKeyFormat
func validateCMACKey(format *cmacpb.AesCmacPrfKeyFormat, key *cmacpb.AesCmacPrfKey) error {
	if format.KeySize != uint32(len(key.KeyValue)) {
		return fmt.Errorf("key format and generated key do not match")
	}
	p, err := subtle.NewAESCMACPRF(key.KeyValue)
	if err != nil {
		return fmt.Errorf("cannot create primitive from key: %s", err)
	}
	return validateCMACPrimitive(p, key)
}

// validateCMACPrimitive checks whether the given primitive matches the given AESCMACPRFKey
func validateCMACPrimitive(p interface{}, key *cmacpb.AesCmacPrfKey) error {
	cmacPrimitive := p.(prf.PRF)
	prfPrimitive, err := subtle.NewAESCMACPRF(key.KeyValue)
	if err != nil {
		return fmt.Errorf("Could not create AES CMAC PRF with key material %q: %s", hex.EncodeToString(key.KeyValue), err)
	}
	data := random.GetRandomBytes(20)
	res, err := cmacPrimitive.ComputePRF(data, 16)
	if err != nil {
		return fmt.Errorf("prf computation failed: %s", err)
	}
	if len(res) != 16 {
		return fmt.Errorf("prf computation did not produce 16 byte output")
	}
	res2, err := prfPrimitive.ComputePRF(data, 16)
	if err != nil {
		return fmt.Errorf("prf computation failed: %s", err)
	}
	if len(res2) != 16 {
		return fmt.Errorf("prf computation did not produce 16 byte output")
	}
	if hex.EncodeToString(res) != hex.EncodeToString(res2) {
		return fmt.Errorf("prf computation did not produce the same output for the same key and input")
	}
	return nil
}
