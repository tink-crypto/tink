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

package mac_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalregistry"
	subtleMac "github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestGetPrimitiveBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("HMAC key manager not found: %s", err)
	}
	testKeys := genValidHMACKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, _ := proto.Marshal(testKeys[i])
		p, err := km.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateHMACPrimitive(p, testKeys[i]); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestGetPrimitiveWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	// invalid key
	testKeys := genInvalidHMACKeys()
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

func TestNewKeyMultipleTimes(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	serializedFormat, _ := proto.Marshal(testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32))
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

func TestNewKeyBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	testFormats := genValidHMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateHMACKey(testFormats[i], key.(*hmacpb.HmacKey)); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestNewKeyWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidHMACKeyFormats()
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

func TestNewKeyDataBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	testFormats := genValidHMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if keyData.TypeUrl != testutil.HMACTypeURL {
			t.Errorf("incorrect type url in test case %d", i)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type in test case %d", i)
		}
		key := new(hmacpb.HmacKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("invalid key value")
		}
		if err := validateHMACKey(testFormats[i], key); err != nil {
			t.Errorf("invalid key")
		}
	}
}

func TestNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("HMAC key manager not found: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidHMACKeyFormats()
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

func TestDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("HMAC key manager not found: %s", err)
	}
	if !km.DoesSupport(testutil.HMACTypeURL) {
		t.Errorf("HMACKeyManager must support %s", testutil.HMACTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("HMACKeyManager must support only %s", testutil.HMACTypeURL)
	}
}

func TestTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("HMAC key manager not found: %s", err)
	}
	if km.TypeURL() != testutil.HMACTypeURL {
		t.Errorf("incorrect GetKeyType()")
	}
}

func TestHMACKeyMaterialType(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACTypeURL, err)
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
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat, err := proto.Marshal(&hmacpb.HmacKeyFormat{
		Version: testutil.HMACKeyVersion,
		KeySize: 16,
		Params: &hmacpb.HmacParams{
			Hash:    commonpb.HashType_SHA256,
			TagSize: 10,
		},
	})
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	rand := random.GetRandomBytes(16)
	buf := &bytes.Buffer{}
	if p, _ := buf.Write(rand); p != len(rand) {
		t.Fatalf("incomplete Write() = %d bytes, want %d bytes", p, len(rand))
	}
	k, err := keyManager.DeriveKey(keyFormat, buf)
	if err != nil {
		t.Fatalf("keyManager.DeriveKey() err = %v, want nil", err)
	}
	key := k.(*hmacpb.HmacKey)
	if got, want := len(key.GetKeyValue()), 16; got != want {
		t.Errorf("key length = %d, want %d", got, want)
	}
	if diff := cmp.Diff(key.GetKeyValue(), rand); diff != "" {
		t.Errorf("incorrect derived key: diff = %v", diff)
	}
}

func TestHMACDeriveKeyFailsWithInvalidKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}

	validKeyFormat := &hmacpb.HmacKeyFormat{
		Version: testutil.HMACKeyVersion,
		KeySize: 16,
		Params: &hmacpb.HmacParams{
			Hash:    commonpb.HashType_SHA256,
			TagSize: 10,
		},
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
		tagSize uint32
	}{
		{
			name:    "invalid version",
			version: 10,
			keySize: validKeyFormat.KeySize,
			hash:    validKeyFormat.Params.Hash,
			tagSize: validKeyFormat.Params.TagSize,
		},
		{
			name:    "invalid key size",
			version: validKeyFormat.Version,
			keySize: 10,
			hash:    validKeyFormat.Params.Hash,
			tagSize: validKeyFormat.Params.TagSize,
		},
		{
			name:    "invalid hash",
			version: validKeyFormat.Version,
			keySize: validKeyFormat.KeySize,
			hash:    commonpb.HashType_UNKNOWN_HASH,
			tagSize: validKeyFormat.Params.TagSize,
		},
		{
			name:    "invalid tag size",
			version: validKeyFormat.Version,
			keySize: validKeyFormat.KeySize,
			hash:    validKeyFormat.Params.Hash,
			tagSize: 9,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyFormat, err := proto.Marshal(&hmacpb.HmacKeyFormat{
				Version: test.version,
				KeySize: test.keySize,
				Params: &hmacpb.HmacParams{
					Hash:    test.hash,
					TagSize: test.tagSize,
				},
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
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACTypeURL, err)
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
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.HMACTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat, err := proto.Marshal(&hmacpb.HmacKeyFormat{
		Version: testutil.HMACKeyVersion,
		KeySize: 16,
		Params: &hmacpb.HmacParams{
			Hash:    commonpb.HashType_SHA256,
			TagSize: 10,
		},
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

func genInvalidHMACKeys() []proto.Message {
	badVersionKey := testutil.NewHMACKey(commonpb.HashType_SHA256, 32)
	badVersionKey.Version++
	shortKey := testutil.NewHMACKey(commonpb.HashType_SHA256, 32)
	shortKey.KeyValue = []byte{1, 1}
	return []proto.Message{
		// not a HMACKey
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// bad version
		badVersionKey,
		// tag size too big
		testutil.NewHMACKey(commonpb.HashType_SHA1, 21),
		testutil.NewHMACKey(commonpb.HashType_SHA256, 33),
		testutil.NewHMACKey(commonpb.HashType_SHA512, 65),
		// tag size too small
		testutil.NewHMACKey(commonpb.HashType_SHA256, 1),
		// key too short
		shortKey,
		// unknown hash type
		testutil.NewHMACKey(commonpb.HashType_UNKNOWN_HASH, 32),
	}
}

func genInvalidHMACKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32)
	shortKeyFormat.KeySize = 1
	return []proto.Message{
		// not a HMACKeyFormat
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// tag size too big
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA1, 21),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 33),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA512, 65),
		// tag size too small
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 1),
		// key too short
		shortKeyFormat,
		// unknown hash type
		testutil.NewHMACKeyFormat(commonpb.HashType_UNKNOWN_HASH, 32),
	}
}

func genValidHMACKeyFormats() []*hmacpb.HmacKeyFormat {
	return []*hmacpb.HmacKeyFormat{
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA1, 20),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA512, 64),
	}
}

func genValidHMACKeys() []*hmacpb.HmacKey {
	return []*hmacpb.HmacKey{
		testutil.NewHMACKey(commonpb.HashType_SHA1, 20),
		testutil.NewHMACKey(commonpb.HashType_SHA256, 32),
		testutil.NewHMACKey(commonpb.HashType_SHA512, 64),
	}
}

// Checks whether the given HMACKey matches the given key HMACKeyFormat
func validateHMACKey(format *hmacpb.HmacKeyFormat, key *hmacpb.HmacKey) error {
	if format.KeySize != uint32(len(key.KeyValue)) ||
		key.Params.TagSize != format.Params.TagSize ||
		key.Params.Hash != format.Params.Hash {
		return fmt.Errorf("key format and generated key do not match")
	}
	p, err := subtleMac.NewHMAC(commonpb.HashType_name[int32(key.Params.Hash)], key.KeyValue, key.Params.TagSize)
	if err != nil {
		return fmt.Errorf("cannot create primitive from key: %s", err)
	}
	return validateHMACPrimitive(p, key)
}

// validateHMACPrimitive checks whether the given primitive matches the given HMACKey
func validateHMACPrimitive(p interface{}, key *hmacpb.HmacKey) error {
	hmacPrimitive := p.(*subtleMac.HMAC)
	if !bytes.Equal(hmacPrimitive.Key, key.KeyValue) ||
		hmacPrimitive.TagSize != key.Params.TagSize ||
		reflect.ValueOf(hmacPrimitive.HashFunc).Pointer() !=
			reflect.ValueOf(subtle.GetHashFunc(commonpb.HashType_name[int32(key.Params.Hash)])).Pointer() {
		return fmt.Errorf("primitive and key do not match")
	}
	data := random.GetRandomBytes(20)
	mac, err := hmacPrimitive.ComputeMAC(data)
	if err != nil {
		return fmt.Errorf("mac computation failed: %s", err)
	}
	if err = hmacPrimitive.VerifyMAC(mac, data); err != nil {
		return fmt.Errorf("mac verification failed: %s", err)
	}
	return nil
}
