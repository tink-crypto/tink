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

package mac_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestGetPrimitiveWorks(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("HMAC key manager not found: %s", err)
	}
	keyValue := random.GetRandomBytes(20)
	testCases := []struct {
		name     string
		key      *hmacpb.HmacKey
		hashName string
		keyValue []byte
		tagSize  uint32
	}{
		{
			name: "SHA1",
			key: &hmacpb.HmacKey{
				Params: &hmacpb.HmacParams{
					Hash:    commonpb.HashType_SHA1,
					TagSize: 20,
				},
				KeyValue: keyValue,
			},
			hashName: "SHA1",
			keyValue: keyValue,
			tagSize:  20,
		}, {
			name: "SHA256",
			key: &hmacpb.HmacKey{
				Params: &hmacpb.HmacParams{
					Hash:    commonpb.HashType_SHA256,
					TagSize: 32,
				},
				KeyValue: keyValue,
			},
			hashName: "SHA256",
			keyValue: keyValue,
			tagSize:  32,
		}, {
			name: "SHA512",
			key: &hmacpb.HmacKey{
				Params: &hmacpb.HmacParams{
					Hash:    commonpb.HashType_SHA512,
					TagSize: 64,
				},
				KeyValue: keyValue,
			},
			hashName: "SHA512",
			keyValue: keyValue,
			tagSize:  64,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serializedKey, err := proto.Marshal(tc.key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %q, want nil", err)
			}
			p, err := km.Primitive(serializedKey)
			if err != nil {
				t.Fatalf("km.Primitive(serializedKey) err = %q, want nil", err)
			}
			mac, ok := p.(tink.MAC)
			if !ok {
				t.Fatal("mac is not a tink.MAC")
			}

			data := random.GetRandomBytes(20)
			tag, err := mac.ComputeMAC(data)
			if err != nil {
				t.Fatalf("mac.ComputeMAC() err = %q, want nil", err)
			}
			if err = mac.VerifyMAC(tag, data); err != nil {
				t.Fatalf("mac.VerifyMAC() err = %q, want nil", err)
			}

			wantMAC, err := subtle.NewHMAC(tc.hashName, tc.keyValue, tc.tagSize)
			if err != nil {
				t.Fatalf("subtle.NewHMAC() err = %v, want nil", err)
			}
			wantTag, err := wantMAC.ComputeMAC(data)
			if err != nil {
				t.Fatalf("wantMAC.ComputeMAC() err = %q, want nil", err)
			}
			if !bytes.Equal(tag, wantTag) {
				t.Errorf("tag = %s, want = %s", tag, wantTag)
			}
		})
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
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
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
	serializedFormat, err := proto.Marshal(testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32))
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	keys := make(map[string]bool)
	nTest := 26
	for i := 0; i < nTest; i++ {
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Fatalf("km.NewKey() err = %q, want nil", err)
		}
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		keys[string(serializedKey)] = true

		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Fatalf("km.NewKeyData() err = %q, want nil", err)
		}
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
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		hmacKey, ok := key.(*hmacpb.HmacKey)
		if !ok {
			t.Errorf("key is not HmacKey")
		}
		format := testFormats[i]
		if format.KeySize != uint32(len(hmacKey.KeyValue)) ||
			hmacKey.Params.TagSize != format.Params.TagSize ||
			hmacKey.Params.Hash != format.Params.Hash {
			t.Errorf("key format and generated key do not match")
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

func TestNewKeyDataWorks(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	testFormats := genValidHMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
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
		format := testFormats[i]
		if format.KeySize != uint32(len(key.KeyValue)) ||
			key.Params.TagSize != format.Params.TagSize ||
			key.Params.Hash != format.Params.Hash {
			t.Errorf("key format and generated key do not match")
		}
		p, err := registry.PrimitiveFromKeyData(keyData)
		if err != nil {
			t.Errorf("registry.PrimitiveFromKeyData(keyData) err = %v, want nil", err)
		}
		_, ok := p.(tink.MAC)
		if !ok {
			t.Error("registry.PrimitiveFromKeyData(keyData) did not return a tink.MAC")
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
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
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
	buf.Write(rand) // never returns a non-nil error
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
	nilParams := testutil.NewHMACKey(commonpb.HashType_SHA256, 32)
	nilParams.Params = nil
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
		// params field is unset
		nilParams,
	}
}

func genInvalidHMACKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32)
	shortKeyFormat.KeySize = 1
	nilParams := testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32)
	nilParams.Params = nil
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
		// params field is unset
		nilParams,
	}
}

func genValidHMACKeyFormats() []*hmacpb.HmacKeyFormat {
	return []*hmacpb.HmacKeyFormat{
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA1, 20),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA512, 64),
	}
}
