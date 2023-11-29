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
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/prf/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestGetPrimitiveHMACBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Errorf("HMAC PRF key manager not found: %s", err)
	}
	testKeys := genValidHMACPRFKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, _ := proto.Marshal(testKeys[i])
		p, err := km.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateHMACPRFPrimitive(p, testKeys[i]); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestGetPrimitiveHMACWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC PRFkey manager: %s", err)
	}
	// invalid key
	testKeys := genInvalidHMACPRFKeys()
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

func TestNewKeyHMACMultipleTimes(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC PRF key manager: %s", err)
	}
	serializedFormat, _ := proto.Marshal(testutil.NewHMACPRFKeyFormat(commonpb.HashType_SHA256))
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

func TestNewKeyHMACBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC PRF key manager: %s", err)
	}
	testFormats := genValidHMACPRFKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateHMACPRFKey(testFormats[i], key.(*hmacpb.HmacPrfKey)); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestNewKeyHMACWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC PRF key manager: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidHMACPRFKeyFormats()
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

func TestNewKeyDataHMACBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC PRF key manager: %s", err)
	}
	testFormats := genValidHMACPRFKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if keyData.TypeUrl != testutil.HMACPRFTypeURL {
			t.Errorf("incorrect type url in test case %d", i)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type in test case %d", i)
		}
		key := new(hmacpb.HmacPrfKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("invalid key value")
		}
		if err := validateHMACPRFKey(testFormats[i], key); err != nil {
			t.Errorf("invalid key")
		}
	}
}

func TestNewKeyDataHMACWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Errorf("HMAC PRF key manager not found: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidHMACPRFKeyFormats()
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

func TestHMACDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Errorf("HMAC PRF key manager not found: %s", err)
	}
	if !km.DoesSupport(testutil.HMACPRFTypeURL) {
		t.Errorf("HMACPRFKeyManager must support %s", testutil.HMACPRFTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("HMACPRFKeyManager must support only %s", testutil.HMACPRFTypeURL)
	}
}

func TestHMACTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Errorf("HMAC PRF key manager not found: %s", err)
	}
	if km.TypeURL() != testutil.HMACPRFTypeURL {
		t.Errorf("incorrect GetKeyType()")
	}
}

func TestHMACKeyMaterialType(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACPRFTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	if got, want := keyManager.KeyMaterialType(), tinkpb.KeyData_SYMMETRIC; got != want {
		t.Errorf("KeyMaterialType() = %v, want %v", got, want)
	}
}

func TestHMACDeriveKey(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACPRFTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat, err := proto.Marshal(&hmacpb.HmacPrfKeyFormat{
		Version: testutil.HMACPRFKeyVersion,
		KeySize: 16,
		Params:  &hmacpb.HmacPrfParams{Hash: commonpb.HashType_SHA256},
	})
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	rand := random.GetRandomBytes(16)
	buf := &bytes.Buffer{}
	buf.Write(rand) // Never returns a non-nil error.
	k, err := keyManager.DeriveKey(keyFormat, buf)
	if err != nil {
		t.Fatalf("keyManager.DeriveKey() err = %v, want nil", err)
	}
	key := k.(*hmacpb.HmacPrfKey)
	if got, want := len(key.GetKeyValue()), 16; got != want {
		t.Errorf("key length = %d, want %d", got, want)
	}
	if diff := cmp.Diff(key.GetKeyValue(), rand); diff != "" {
		t.Errorf("incorrect derived key: diff = %v", diff)
	}
}

func TestHMACDeriveKeyFailsWithInvalidKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACPRFTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}

	validKeyFormat := &hmacpb.HmacPrfKeyFormat{
		Version: testutil.HMACPRFKeyVersion,
		KeySize: 16,
		Params:  &hmacpb.HmacPrfParams{Hash: commonpb.HashType_SHA256},
	}
	serializedValidKeyFormat, err := proto.Marshal(validKeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", validKeyFormat, err)
	}
	buf := bytes.NewBuffer(random.GetRandomBytes(validKeyFormat.KeySize))
	if _, err := keyManager.DeriveKey(serializedValidKeyFormat, buf); err != nil {
		t.Fatalf("keyManager.DeriveKey() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name    string
		version uint32
		keySize uint32
		hash    commonpb.HashType
	}{
		{
			name:    "invalid version",
			version: 10,
			keySize: validKeyFormat.KeySize,
			hash:    validKeyFormat.Params.Hash,
		},
		{
			name:    "invalid key size",
			version: validKeyFormat.Version,
			keySize: 10,
			hash:    validKeyFormat.Params.Hash,
		},
		{
			name:    "invalid hash",
			version: validKeyFormat.Version,
			keySize: validKeyFormat.KeySize,
			hash:    commonpb.HashType_UNKNOWN_HASH,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyFormat, err := proto.Marshal(&hmacpb.HmacPrfKeyFormat{
				Version: test.version,
				KeySize: test.keySize,
				Params:  &hmacpb.HmacPrfParams{Hash: test.hash},
			})
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			buf := bytes.NewBuffer(random.GetRandomBytes(test.keySize))
			if _, err := keyManager.DeriveKey(keyFormat, buf); err == nil {
				t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
			}
		})
	}
}

func TestHMACDeriveKeyFailsWithMalformedKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACPRFTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	// Proto messages start with a VarInt, which always ends with a byte with the
	// MSB unset, so 0x80 is invalid.
	invalidSerialization, err := hex.DecodeString("80")
	if err != nil {
		t.Errorf("hex.DecodeString() err = %v, want nil", err)
	}
	for _, test := range []struct {
		name      string
		keyFormat []byte
	}{
		{
			name:      "nil",
			keyFormat: nil,
		},
		{
			name:      "empty",
			keyFormat: []byte{},
		},
		{
			name:      "invalid serialization",
			keyFormat: invalidSerialization,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			buf := bytes.NewBuffer(random.GetRandomBytes(16))
			if _, err := keyManager.DeriveKey(test.keyFormat, buf); err == nil {
				t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
			}
		})
	}
}

func TestHMACDeriveKeyFailsWithInsufficientRandomness(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACPRFTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat, err := proto.Marshal(&hmacpb.HmacPrfKeyFormat{
		Version: testutil.HMACPRFKeyVersion,
		KeySize: 16,
		Params:  &hmacpb.HmacPrfParams{Hash: commonpb.HashType_SHA256},
	})
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyFormat, err)
	}
	{
		buf := bytes.NewBuffer(random.GetRandomBytes(16))
		if _, err := keyManager.DeriveKey(keyFormat, buf); err != nil {
			t.Errorf("keyManager.DeriveKey() err = %v, want nil", err)
		}
	}
	{
		insufficientBuf := bytes.NewBuffer(random.GetRandomBytes(15))
		if _, err := keyManager.DeriveKey(keyFormat, insufficientBuf); err == nil {
			t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
		}
	}
}

func genInvalidHMACPRFKeys() []proto.Message {
	badVersionKey := testutil.NewHMACPRFKey(commonpb.HashType_SHA256)
	badVersionKey.Version++
	shortKey := testutil.NewHMACPRFKey(commonpb.HashType_SHA256)
	shortKey.KeyValue = []byte{1, 1}
	nilParams := testutil.NewHMACPRFKey(commonpb.HashType_SHA256)
	nilParams.Params = nil
	return []proto.Message{
		// not a HMACPRFKey
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// bad version
		badVersionKey,
		// key too short
		shortKey,
		// unknown hash type
		testutil.NewHMACPRFKey(commonpb.HashType_UNKNOWN_HASH),
		// params field is unset
		nilParams,
	}
}

func genInvalidHMACPRFKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewHMACPRFKeyFormat(commonpb.HashType_SHA256)
	shortKeyFormat.KeySize = 1
	nilParams := testutil.NewHMACPRFKey(commonpb.HashType_SHA256)
	nilParams.Params = nil
	return []proto.Message{
		// not a HMACPRFKeyFormat
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// key too short
		shortKeyFormat,
		// unknown hash type
		testutil.NewHMACPRFKeyFormat(commonpb.HashType_UNKNOWN_HASH),
		// params field is unset
		nilParams,
	}
}

func genValidHMACPRFKeyFormats() []*hmacpb.HmacPrfKeyFormat {
	return []*hmacpb.HmacPrfKeyFormat{
		testutil.NewHMACPRFKeyFormat(commonpb.HashType_SHA1),
		testutil.NewHMACPRFKeyFormat(commonpb.HashType_SHA256),
		testutil.NewHMACPRFKeyFormat(commonpb.HashType_SHA512),
	}
}

func genValidHMACPRFKeys() []*hmacpb.HmacPrfKey {
	return []*hmacpb.HmacPrfKey{
		testutil.NewHMACPRFKey(commonpb.HashType_SHA1),
		testutil.NewHMACPRFKey(commonpb.HashType_SHA256),
		testutil.NewHMACPRFKey(commonpb.HashType_SHA512),
	}
}

// Checks whether the given HMACPRFKey matches the given key HMACPRFKeyFormat
func validateHMACPRFKey(format *hmacpb.HmacPrfKeyFormat, key *hmacpb.HmacPrfKey) error {
	if format.KeySize != uint32(len(key.KeyValue)) ||
		key.Params.Hash != format.Params.Hash {
		return fmt.Errorf("key format and generated key do not match")
	}
	p, err := subtle.NewHMACPRF(commonpb.HashType_name[int32(key.Params.Hash)], key.KeyValue)
	if err != nil {
		return fmt.Errorf("cannot create primitive from key: %s", err)
	}
	return validateHMACPRFPrimitive(p, key)
}

// validateHMACPRFPrimitive checks whether the given primitive can compute a PRF of length 16
func validateHMACPRFPrimitive(p interface{}, key *hmacpb.HmacPrfKey) error {
	hmac := p.(prf.PRF)
	prfPrimitive, err := subtle.NewHMACPRF(commonpb.HashType_name[int32(key.Params.Hash)], key.KeyValue)
	if err != nil {
		return fmt.Errorf("Could not create HMAC PRF with key material %q: %s", hex.EncodeToString(key.KeyValue), err)
	}
	data := random.GetRandomBytes(20)
	res, err := hmac.ComputePRF(data, 16)
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
