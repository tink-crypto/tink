// Copyright 2019 Google LLC
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

package daead_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"

	"github.com/google/tink/go/daead/subtle"
	aspb "github.com/google/tink/go/proto/aes_siv_go_proto"
	tpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestAESSIVPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AESSIV key manager: %s", err)
	}
	m, err := km.NewKey(nil)
	if err != nil {
		t.Errorf("km.NewKey(nil) = _, %v; want _, nil", err)
	}
	key, ok := m.(*aspb.AesSivKey)
	if !ok {
		t.Errorf("m is not *aspb.AesSivKey")
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Errorf("proto.Marshal() = %q; want nil", err)
	}
	p, err := km.Primitive(serializedKey)
	if err != nil {
		t.Errorf("km.Primitive(%v) = %v; want nil", serializedKey, err)
	}
	if err := validateAESSIVPrimitive(p, key); err != nil {
		t.Errorf("validateAESSIVPrimitive(p, key) = %v; want nil", err)
	}
}

func TestAESSIVPrimitiveWithInvalidKeys(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESSIV key manager: %s", err)
	}
	invalidKeys := []*aspb.AesSivKey{
		// Bad key size.
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion,
			KeyValue: random.GetRandomBytes(16),
		},
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion,
			KeyValue: random.GetRandomBytes(32),
		},
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion,
			KeyValue: random.GetRandomBytes(63),
		},
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion,
			KeyValue: random.GetRandomBytes(65),
		},
		// Bad version.
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion + 1,
			KeyValue: random.GetRandomBytes(subtle.AESSIVKeySize),
		},
	}
	for _, key := range invalidKeys {
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Errorf("proto.Marshal() = %q; want nil", err)
		}
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("km.Primitive(%v) = _, nil; want _, err", serializedKey)
		}
	}
}

func TestAESSIVNewKey(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESSIV key manager: %s", err)
	}
	m, err := km.NewKey(nil)
	if err != nil {
		t.Errorf("km.NewKey(nil) = _, %v; want _, nil", err)
	}
	key, ok := m.(*aspb.AesSivKey)
	if !ok {
		t.Errorf("m is not *aspb.AesSivKey")
	}
	if err := validateAESSIVKey(key); err != nil {
		t.Errorf("validateAESSIVKey(%v) = %v; want nil", key, err)
	}
}

func TestAESSIVNewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESSIV key manager: %s", err)
	}
	kd, err := km.NewKeyData(nil)
	if err != nil {
		t.Errorf("km.NewKeyData(nil) = _, %v; want _, nil", err)
	}
	if kd.TypeUrl != testutil.AESSIVTypeURL {
		t.Errorf("TypeUrl: %v != %v", kd.TypeUrl, testutil.AESSIVTypeURL)
	}
	if kd.KeyMaterialType != tpb.KeyData_SYMMETRIC {
		t.Errorf("KeyMaterialType: %v != SYMMETRIC", kd.KeyMaterialType)
	}
	key := new(aspb.AesSivKey)
	if err := proto.Unmarshal(kd.Value, key); err != nil {
		t.Errorf("proto.Unmarshal(%v, key) = %v; want nil", kd.Value, err)
	}
	if err := validateAESSIVKey(key); err != nil {
		t.Errorf("validateAESSIVKey(%v) = %v; want nil", key, err)
	}
}

func TestAESSIVNewKeyInvalid(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESSIVTypeURL, err)
	}
	invalidKeySize, err := proto.Marshal(&aspb.AesSivKeyFormat{
		KeySize: subtle.AESSIVKeySize - 1,
		Version: testutil.AESSIVKeyVersion,
	})
	if err != nil {
		t.Errorf("proto.Marshal() err = %v, want nil", err)
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
			name:      "invalid key size",
			keyFormat: invalidKeySize,
		},
		{
			name:      "invalid serialization",
			keyFormat: invalidSerialization,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err = km.NewKey(test.keyFormat); err == nil {
				t.Error("km.NewKey() err = nil, want non-nil")
			}
		})
	}
}

func TestAESSIVDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESSIV key manager: %s", err)
	}
	if !km.DoesSupport(testutil.AESSIVTypeURL) {
		t.Errorf("AESSIVKeyManager must support %s", testutil.AESSIVTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("AESSIVKeyManager must only support %s", testutil.AESSIVTypeURL)
	}
}

func TestAESSIVTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESSIV key manager: %s", err)
	}
	if kt := km.TypeURL(); kt != testutil.AESSIVTypeURL {
		t.Errorf("km.TypeURL() = %s; want %s", kt, testutil.AESSIVTypeURL)
	}
}

func TestAESSIVKeyMaterialType(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESSIVTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	if got, want := keyManager.KeyMaterialType(), tpb.KeyData_SYMMETRIC; got != want {
		t.Errorf("KeyMaterialType() = %v, want %v", got, want)
	}
}

func TestAESSIVDeriveKey(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESSIVTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat, err := proto.Marshal(&aspb.AesSivKeyFormat{
		KeySize: subtle.AESSIVKeySize,
		Version: testutil.AESSIVKeyVersion,
	})
	if err != nil {
		t.Errorf("proto.Marshal() = %v; want nil", err)
	}
	rand := random.GetRandomBytes(subtle.AESSIVKeySize)
	buf := &bytes.Buffer{}
	buf.Write(rand) // never returns a non-nil error
	k, err := keyManager.DeriveKey(keyFormat, buf)
	if err != nil {
		t.Fatalf("keyManager.DeriveKey() err = %v, want nil", err)
	}
	key := k.(*aspb.AesSivKey)
	if got, want := len(key.GetKeyValue()), subtle.AESSIVKeySize; got != want {
		t.Errorf("key length = %d, want %d", got, want)
	}
	if diff := cmp.Diff(key.GetKeyValue(), rand); diff != "" {
		t.Errorf("incorrect derived key: diff = %v", diff)
	}
}

func TestAESSIVDeriveKeyFailsWithInvalidKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESSIVTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	for _, test := range []struct {
		name    string
		keySize uint32
		version uint32
	}{
		{
			name:    "invalid key size",
			keySize: subtle.AESSIVKeySize - 1,
			version: testutil.AESSIVKeyVersion,
		},
		{
			name:    "invalid version",
			keySize: subtle.AESSIVKeySize,
			version: testutil.AESSIVKeyVersion + 1,
		},
		{
			name:    "zero key size and version",
			keySize: 0,
			version: 0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyFormat := &aspb.AesSivKeyFormat{
				KeySize: test.keySize,
				Version: test.version,
			}
			serializedKeyFormat, err := proto.Marshal(keyFormat)
			if err != nil {
				t.Errorf("proto.Marshal() = %v; want nil", err)
			}
			buf := bytes.NewBuffer(random.GetRandomBytes(subtle.AESSIVKeySize))
			if _, err := keyManager.DeriveKey(serializedKeyFormat, buf); err == nil {
				t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
			}
		})
	}
}

func TestAESSIVDeriveKeyFailsWithMalformedKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESSIVTypeURL, err)
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
			name:      "invalid serialization",
			keyFormat: invalidSerialization,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			buf := bytes.NewBuffer(random.GetRandomBytes(subtle.AESSIVKeySize))
			if _, err := keyManager.DeriveKey(test.keyFormat, buf); err == nil {
				t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
			}
		})
	}
}

func TestAESSIVDeriveKeyFailsWithInsufficientRandomness(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESSIVTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat, err := proto.Marshal(&aspb.AesSivKeyFormat{
		KeySize: subtle.AESSIVKeySize,
		Version: testutil.AESSIVKeyVersion,
	})
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	{
		buf := bytes.NewBuffer(random.GetRandomBytes(subtle.AESSIVKeySize))
		if _, err := keyManager.DeriveKey(keyFormat, buf); err != nil {
			t.Errorf("keyManager.DeriveKey() err = %v, want nil", err)
		}
	}
	{
		insufficientBuf := bytes.NewBuffer(random.GetRandomBytes(subtle.AESSIVKeySize - 1))
		if _, err := keyManager.DeriveKey(keyFormat, insufficientBuf); err == nil {
			t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
		}
	}
}

func validateAESSIVPrimitive(p interface{}, key *aspb.AesSivKey) error {
	cipher := p.(*subtle.AESSIV)
	// try to encrypt and decrypt
	pt := random.GetRandomBytes(32)
	aad := random.GetRandomBytes(32)
	ct, err := cipher.EncryptDeterministically(pt, aad)
	if err != nil {
		return fmt.Errorf("encryption failed")
	}
	decrypted, err := cipher.DecryptDeterministically(ct, aad)
	if err != nil {
		return fmt.Errorf("decryption failed")
	}
	if !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed")
	}
	return nil
}

func validateAESSIVKey(key *aspb.AesSivKey) error {
	if key.Version != testutil.AESSIVKeyVersion {
		return fmt.Errorf("incorrect key version: keyVersion != %d", testutil.AESSIVKeyVersion)
	}
	if uint32(len(key.KeyValue)) != subtle.AESSIVKeySize {
		return fmt.Errorf("incorrect key size: keySize != %d", subtle.AESSIVKeySize)
	}

	// Try to encrypt and decrypt.
	p, err := subtle.NewAESSIV(key.KeyValue)
	if err != nil {
		return fmt.Errorf("invalid key: %v", key.KeyValue)
	}
	return validateAESSIVPrimitive(p, key)
}
