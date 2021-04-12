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

package mac_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/mac/subtle"
	subtleMac "github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	cmacpb "github.com/google/tink/go/proto/aes_cmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestGetPrimitiveCMACBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("AESCMAC key manager not found: %s", err)
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
	km, err := registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESCMAC key manager: %s", err)
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
	km, err := registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESCMAC key manager: %s", err)
	}
	serializedFormat, _ := proto.Marshal(testutil.NewAESCMACKeyFormat(16))
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
	km, err := registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESCMAC key manager: %s", err)
	}
	testFormats := genValidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateCMACKey(testFormats[i], key.(*cmacpb.AesCmacKey)); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestNewKeyCMACWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESCMAC key manager: %s", err)
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
	km, err := registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESCMAC key manager: %s", err)
	}
	testFormats := genValidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if keyData.TypeUrl != testutil.AESCMACTypeURL {
			t.Errorf("incorrect type url in test case %d", i)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type in test case %d", i)
		}
		key := new(cmacpb.AesCmacKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("invalid key value")
		}
		if err := validateCMACKey(testFormats[i], key); err != nil {
			t.Errorf("invalid key")
		}
	}
}

func TestNewKeyDataCMACWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("AESCMAC key manager not found: %s", err)
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

func TestDoesSupportCMAC(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("AESCMAC key manager not found: %s", err)
	}
	if !km.DoesSupport(testutil.AESCMACTypeURL) {
		t.Errorf("AESCMACKeyManager must support %s", testutil.AESCMACTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("AESCMACKeyManager must support only %s", testutil.AESCMACTypeURL)
	}
}

func TestTypeURLCMAC(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("AESCMAC key manager not found: %s", err)
	}
	if km.TypeURL() != testutil.AESCMACTypeURL {
		t.Errorf("incorrect GetKeyType()")
	}
}

func genInvalidCMACKeys() []proto.Message {
	badVersionKey := testutil.NewAESCMACKey(16)
	badVersionKey.Version++
	shortKey := testutil.NewAESCMACKey(16)
	shortKey.KeyValue = []byte{1, 1}
	return []proto.Message{
		// not a AESCMACKey
		testutil.NewAESCMACParams(16),
		// bad version
		badVersionKey,
		// tag size too big
		testutil.NewAESCMACKey(17),
		// tag size too small
		testutil.NewAESCMACKey(1),
		// key too short
		shortKey,
	}
}

func genInvalidCMACKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewAESCMACKeyFormat(16)
	shortKeyFormat.KeySize = 1
	return []proto.Message{
		// not a AESCMACKeyFormat
		testutil.NewAESCMACParams(16),
		// tag size too big
		testutil.NewAESCMACKeyFormat(17),
		// tag size too small
		testutil.NewAESCMACKeyFormat(1),
		// key too short
		shortKeyFormat,
	}
}

func genValidCMACKeyFormats() []*cmacpb.AesCmacKeyFormat {
	return []*cmacpb.AesCmacKeyFormat{
		testutil.NewAESCMACKeyFormat(10),
		testutil.NewAESCMACKeyFormat(16),
	}
}

func genValidCMACKeys() []*cmacpb.AesCmacKey {
	return []*cmacpb.AesCmacKey{
		testutil.NewAESCMACKey(10),
		testutil.NewAESCMACKey(16),
	}
}

// Checks whether the given AESCMACKey matches the given key AESCMACKeyFormat
func validateCMACKey(format *cmacpb.AesCmacKeyFormat, key *cmacpb.AesCmacKey) error {
	if format.KeySize != uint32(len(key.KeyValue)) ||
		key.Params.TagSize != format.Params.TagSize {
		return fmt.Errorf("key format and generated key do not match")
	}
	p, err := subtleMac.NewAESCMAC(key.KeyValue, key.Params.TagSize)
	if err != nil {
		return fmt.Errorf("cannot create primitive from key: %s", err)
	}
	return validateCMACPrimitive(p, key)
}

// validateCMACPrimitive checks whether the given primitive matches the given AESCMACKey
func validateCMACPrimitive(p interface{}, key *cmacpb.AesCmacKey) error {
	cmacPrimitive := p.(*subtleMac.AESCMAC)
	keyPrimitive, err := subtle.NewAESCMAC(key.KeyValue, key.Params.TagSize)
	if err != nil {
		return fmt.Errorf("Could not create AES CMAC with key material %q and tag size %d: %s", hex.EncodeToString(key.KeyValue), key.Params.TagSize, err)
	}
	data := random.GetRandomBytes(20)
	mac, err := cmacPrimitive.ComputeMAC(data)
	if err != nil {
		return fmt.Errorf("mac computation failed: %s", err)
	}
	keyMac, err := keyPrimitive.ComputeMAC(data)
	if err != nil {
		return fmt.Errorf("mac computation with provided key failed: %s", err)
	}
	if err = cmacPrimitive.VerifyMAC(mac, data); err != nil {
		return fmt.Errorf("mac self verification failed: %s", err)
	}
	if err = cmacPrimitive.VerifyMAC(keyMac, data); err != nil {
		return fmt.Errorf("mac computed with the provided key could not be verified: %s", err)
	}
	if err = keyPrimitive.VerifyMAC(mac, data); err != nil {
		return fmt.Errorf("mac could not be verified by primitive using the provided key: %s", err)
	}
	if err = keyPrimitive.VerifyMAC(keyMac, data); err != nil {
		return fmt.Errorf("mac self verification of mac created with the provided key failed: %s", err)
	}
	return nil
}
