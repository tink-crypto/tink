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
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestGetPrimitiveHKDFBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Errorf("HKDF PRF key manager not found: %s", err)
	}
	testKeys := genValidHKDFKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, _ := proto.Marshal(testKeys[i])
		p, err := km.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateHKDFPrimitive(p, testKeys[i]); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestGetPrimitiveHKDFWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HKDF PRF key manager: %s", err)
	}
	// invalid key
	testKeys := genInvalidHKDFKeys()
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

func TestNewKeyHKDFMultipleTimes(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HKDF PRF key manager: %s", err)
	}
	serializedFormat, _ := proto.Marshal(testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA256, make([]byte, 0)))
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

func TestNewKeyHKDFBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HKDF PRF key manager: %s", err)
	}
	testFormats := genValidHKDFKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateHKDFKey(testFormats[i], key.(*hkdfpb.HkdfPrfKey)); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestNewKeyHKDFWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HKDF PRF key manager: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidHKDFKeyFormats()
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

func TestNewKeyDataHKDFBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HKDF PRF key manager: %s", err)
	}
	testFormats := genValidHKDFKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if keyData.TypeUrl != testutil.HKDFPRFTypeURL {
			t.Errorf("incorrect type url in test case %d", i)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type in test case %d", i)
		}
		key := new(hkdfpb.HkdfPrfKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("invalid key value")
		}
		if err := validateHKDFKey(testFormats[i], key); err != nil {
			t.Errorf("invalid key")
		}
	}
}

func TestNewKeyDataHKDFWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Errorf("HKDF PRF key manager not found: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidHKDFKeyFormats()
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

func TestHKDFDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Errorf("HKDF PRF key manager not found: %s", err)
	}
	if !km.DoesSupport(testutil.HKDFPRFTypeURL) {
		t.Errorf("HKDFPRFKeyManager must support %s", testutil.HKDFPRFTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("HKDFPRFKeyManager must support only %s", testutil.HKDFPRFTypeURL)
	}
}

func TestHKDFTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Errorf("HKDF PRF key manager not found: %s", err)
	}
	if km.TypeURL() != testutil.HKDFPRFTypeURL {
		t.Errorf("incorrect GetKeyType()")
	}
}

func genInvalidHKDFKeys() []proto.Message {
	badVersionKey := testutil.NewHKDFPRFKey(commonpb.HashType_SHA256, make([]byte, 0))
	badVersionKey.Version++
	shortKey := testutil.NewHKDFPRFKey(commonpb.HashType_SHA256, make([]byte, 0))
	shortKey.KeyValue = []byte{1, 1}
	return []proto.Message{
		// not a HKDFPRFKey
		testutil.NewHKDFPRFParams(commonpb.HashType_SHA256, make([]byte, 0)),
		// bad version
		badVersionKey,
		// key too short
		shortKey,
		// SHA-1
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA1, make([]byte, 0)),
		// unknown hash type
		testutil.NewHKDFPRFKey(commonpb.HashType_UNKNOWN_HASH, make([]byte, 0)),
	}
}

func genInvalidHKDFKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA256, make([]byte, 0))
	shortKeyFormat.KeySize = 1
	return []proto.Message{
		// not a HKDFPRFKeyFormat
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// key too short
		shortKeyFormat,
		// SHA-1
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA1, make([]byte, 0)),
		// unknown hash type
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_UNKNOWN_HASH, make([]byte, 0)),
	}
}

func genValidHKDFKeyFormats() []*hkdfpb.HkdfPrfKeyFormat {
	return []*hkdfpb.HkdfPrfKeyFormat{
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA256, make([]byte, 0)),
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA512, make([]byte, 0)),
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA256, []byte{0x01, 0x03, 0x42}),
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA512, []byte{0x01, 0x03, 0x42}),
	}
}

func genValidHKDFKeys() []*hkdfpb.HkdfPrfKey {
	return []*hkdfpb.HkdfPrfKey{
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA256, make([]byte, 0)),
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA512, make([]byte, 0)),
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA256, []byte{0x01, 0x03, 0x42}),
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA512, []byte{0x01, 0x03, 0x42}),
	}
}

// Checks whether the given HKDFPRFKey matches the given key HKDFPRFKeyFormat
func validateHKDFKey(format *hkdfpb.HkdfPrfKeyFormat, key *hkdfpb.HkdfPrfKey) error {
	if format.KeySize != uint32(len(key.KeyValue)) ||
		key.Params.Hash != format.Params.Hash {
		return fmt.Errorf("key format and generated key do not match")
	}
	p, err := subtle.NewHKDFPRF(commonpb.HashType_name[int32(key.Params.Hash)], key.KeyValue, key.Params.Salt)
	if err != nil {
		return fmt.Errorf("cannot create primitive from key: %s", err)
	}
	return validateHKDFPrimitive(p, key)
}

// validateHKDFPrimitive checks whether the given primitive matches the given HKDFPRFKey
func validateHKDFPrimitive(p interface{}, key *hkdfpb.HkdfPrfKey) error {
	hkdfPrimitive := p.(prf.PRF)
	prfPrimitive, err := subtle.NewHKDFPRF(commonpb.HashType_name[int32(key.Params.Hash)], key.KeyValue, key.Params.Salt)
	if err != nil {
		return fmt.Errorf("Could not create HKDF PRF with key material %q: %s", hex.EncodeToString(key.KeyValue), err)
	}
	data := random.GetRandomBytes(20)
	res, err := hkdfPrimitive.ComputePRF(data, 16)
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
