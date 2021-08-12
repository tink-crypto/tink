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
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"

	"github.com/google/tink/go/daead/subtle"
	aspb "github.com/google/tink/go/proto/aes_siv_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
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
	key, _ := m.(*aspb.AesSivKey)
	serializedKey, _ := proto.Marshal(key)
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
	invalidKeys := genInvalidAESSIVKeys()
	for _, key := range invalidKeys {
		serializedKey, _ := proto.Marshal(key)
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
	key, _ := m.(*aspb.AesSivKey)
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
	if kd.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
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
		t.Errorf("cannot obtain AESSIV key manager: %s", err)
	}
	keyFormat := &aspb.AesSivKeyFormat{
		KeySize: subtle.AESSIVKeySize - 1,
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		t.Errorf("proto.Marshal(keyFormat) = %v; want nil", err)
	}
	_, err = km.NewKey(serializedKeyFormat)
	if err == nil {
		t.Errorf("km.NewKey(serializedKeyFormat) = _, nil; want _, err")
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

func genInvalidAESSIVKeys() []*aspb.AesSivKey {
	return []*aspb.AesSivKey{
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
}
