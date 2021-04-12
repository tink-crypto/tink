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

package aead_test

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"

	"github.com/google/tink/go/aead/subtle"
	cppb "github.com/google/tink/go/proto/chacha20_poly1305_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestChaCha20Poly1305GetPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain ChaCha20Poly1305 key manager: %s", err)
	}
	m, _ := km.NewKey(nil)
	key, _ := m.(*cppb.ChaCha20Poly1305Key)
	serializedKey, _ := proto.Marshal(key)
	p, err := km.Primitive(serializedKey)
	if err != nil {
		t.Errorf("km.Primitive(%v) = %v; want nil", serializedKey, err)
	}
	if err := validateChaCha20Poly1305Primitive(p, key); err != nil {
		t.Errorf("validateChaCha20Poly1305Primitive(p, key) = %v; want nil", err)
	}
}

func TestChaCha20Poly1305GetPrimitiveWithInvalidKeys(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain ChaCha20Poly1305 key manager: %s", err)
	}
	invalidKeys := genInvalidChaCha20Poly1305Keys()
	for _, key := range invalidKeys {
		serializedKey, _ := proto.Marshal(key)
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("km.Primitive(%v) = _, nil; want _, err", serializedKey)
		}
	}
}

func TestChaCha20Poly1305NewKey(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain ChaCha20Poly1305 key manager: %s", err)
	}
	m, err := km.NewKey(nil)
	if err != nil {
		t.Errorf("km.NewKey(nil) = _, %v; want _, nil", err)
	}
	key, _ := m.(*cppb.ChaCha20Poly1305Key)
	if err := validateChaCha20Poly1305Key(key); err != nil {
		t.Errorf("validateChaCha20Poly1305Key(%v) = %v; want nil", key, err)
	}
}

func TestChaCha20Poly1305NewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain ChaCha20Poly1305 key manager: %s", err)
	}
	kd, err := km.NewKeyData(nil)
	if err != nil {
		t.Errorf("km.NewKeyData(nil) = _, %v; want _, nil", err)
	}
	if kd.TypeUrl != testutil.ChaCha20Poly1305TypeURL {
		t.Errorf("TypeUrl: %v != %v", kd.TypeUrl, testutil.ChaCha20Poly1305TypeURL)
	}
	if kd.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
		t.Errorf("KeyMaterialType: %v != SYMMETRIC", kd.KeyMaterialType)
	}
	key := new(cppb.ChaCha20Poly1305Key)
	if err := proto.Unmarshal(kd.Value, key); err != nil {
		t.Errorf("proto.Unmarshal(%v, key) = %v; want nil", kd.Value, err)
	}
	if err := validateChaCha20Poly1305Key(key); err != nil {
		t.Errorf("validateChaCha20Poly1305Key(%v) = %v; want nil", key, err)
	}
}

func TestChaCha20Poly1305DoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain ChaCha20Poly1305 key manager: %s", err)
	}
	if !km.DoesSupport(testutil.ChaCha20Poly1305TypeURL) {
		t.Errorf("ChaCha20Poly1305KeyManager must support %s", testutil.ChaCha20Poly1305TypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("ChaCha20Poly1305KeyManager must only support %s", testutil.ChaCha20Poly1305TypeURL)
	}
}

func TestChaCha20Poly1305TypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.ChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain ChaCha20Poly1305 key manager: %s", err)
	}
	if kt := km.TypeURL(); kt != testutil.ChaCha20Poly1305TypeURL {
		t.Errorf("km.TypeURL() = %s; want %s", kt, testutil.ChaCha20Poly1305TypeURL)
	}
}

func genInvalidChaCha20Poly1305Keys() []*cppb.ChaCha20Poly1305Key {
	return []*cppb.ChaCha20Poly1305Key{
		// Bad key size.
		&cppb.ChaCha20Poly1305Key{
			Version:  testutil.ChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(17),
		},
		&cppb.ChaCha20Poly1305Key{
			Version:  testutil.ChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(25),
		},
		&cppb.ChaCha20Poly1305Key{
			Version:  testutil.ChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(33),
		},
		// Bad version.
		&cppb.ChaCha20Poly1305Key{
			Version:  testutil.ChaCha20Poly1305KeyVersion + 1,
			KeyValue: random.GetRandomBytes(chacha20poly1305.KeySize),
		},
	}
}

func validateChaCha20Poly1305Primitive(p interface{}, key *cppb.ChaCha20Poly1305Key) error {
	cipher := p.(*subtle.ChaCha20Poly1305)
	if !bytes.Equal(cipher.Key, key.KeyValue) {
		return fmt.Errorf("key and primitive don't match")
	}

	// Try to encrypt and decrypt.
	pt := random.GetRandomBytes(32)
	aad := random.GetRandomBytes(32)
	ct, err := cipher.Encrypt(pt, aad)
	if err != nil {
		return fmt.Errorf("encryption failed")
	}
	decrypted, err := cipher.Decrypt(ct, aad)
	if err != nil {
		return fmt.Errorf("decryption failed")
	}
	if !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed")
	}
	return nil
}

func validateChaCha20Poly1305Key(key *cppb.ChaCha20Poly1305Key) error {
	if key.Version != testutil.ChaCha20Poly1305KeyVersion {
		return fmt.Errorf("incorrect key version: keyVersion != %d", testutil.ChaCha20Poly1305KeyVersion)
	}
	if uint32(len(key.KeyValue)) != chacha20poly1305.KeySize {
		return fmt.Errorf("incorrect key size: keySize != %d", chacha20poly1305.KeySize)
	}

	// Try to encrypt and decrypt.
	p, err := subtle.NewChaCha20Poly1305(key.KeyValue)
	if err != nil {
		return fmt.Errorf("invalid key: %v", key.KeyValue)
	}
	return validateChaCha20Poly1305Primitive(p, key)
}
