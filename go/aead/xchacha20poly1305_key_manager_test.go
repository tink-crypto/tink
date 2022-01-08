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
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"

	"github.com/google/tink/go/aead/subtle"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	xcppb "github.com/google/tink/go/proto/xchacha20_poly1305_go_proto"
)

func TestXChaCha20Poly1305GetPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain XChaCha20Poly1305 key manager: %s", err)
	}
	m, _ := km.NewKey(nil)
	key, _ := m.(*xcppb.XChaCha20Poly1305Key)
	serializedKey, _ := proto.Marshal(key)
	p, err := km.Primitive(serializedKey)
	if err != nil {
		t.Errorf("km.Primitive(%v) = %v; want nil", serializedKey, err)
	}
	if err := validateXChaCha20Poly1305Primitive(p, key); err != nil {
		t.Errorf("validateXChaCha20Poly1305Primitive(p, key) = %v; want nil", err)
	}
}

func TestXChaCha20Poly1305GetPrimitiveWithInvalidKeys(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain XChaCha20Poly1305 key manager: %s", err)
	}
	invalidKeys := genInvalidXChaCha20Poly1305Keys()
	for _, key := range invalidKeys {
		serializedKey, _ := proto.Marshal(key)
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("km.Primitive(%v) = _, nil; want _, err", serializedKey)
		}
	}
}

func TestXChaCha20Poly1305NewKey(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain XChaCha20Poly1305 key manager: %s", err)
	}
	m, err := km.NewKey(nil)
	if err != nil {
		t.Errorf("km.NewKey(nil) = _, %v; want _, nil", err)
	}
	key, _ := m.(*xcppb.XChaCha20Poly1305Key)
	if err := validateXChaCha20Poly1305Key(key); err != nil {
		t.Errorf("validateXChaCha20Poly1305Key(%v) = %v; want nil", key, err)
	}
}

func TestXChaCha20Poly1305NewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain XChaCha20Poly1305 key manager: %s", err)
	}
	kd, err := km.NewKeyData(nil)
	if err != nil {
		t.Errorf("km.NewKeyData(nil) = _, %v; want _, nil", err)
	}
	if kd.TypeUrl != testutil.XChaCha20Poly1305TypeURL {
		t.Errorf("TypeUrl: %v != %v", kd.TypeUrl, testutil.XChaCha20Poly1305TypeURL)
	}
	if kd.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
		t.Errorf("KeyMaterialType: %v != SYMMETRIC", kd.KeyMaterialType)
	}
	key := new(xcppb.XChaCha20Poly1305Key)
	if err := proto.Unmarshal(kd.Value, key); err != nil {
		t.Errorf("proto.Unmarshal(%v, key) = %v; want nil", kd.Value, err)
	}
	if err := validateXChaCha20Poly1305Key(key); err != nil {
		t.Errorf("validateXChaCha20Poly1305Key(%v) = %v; want nil", key, err)
	}
}

func TestXChaCha20Poly1305DoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain XChaCha20Poly1305 key manager: %s", err)
	}
	if !km.DoesSupport(testutil.XChaCha20Poly1305TypeURL) {
		t.Errorf("XChaCha20Poly1305KeyManager must support %s", testutil.XChaCha20Poly1305TypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("XChaCha20Poly1305KeyManager must only support %s", testutil.XChaCha20Poly1305TypeURL)
	}
}

func TestXChaCha20Poly1305TypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain XChaCha20Poly1305 key manager: %s", err)
	}
	if kt := km.TypeURL(); kt != testutil.XChaCha20Poly1305TypeURL {
		t.Errorf("km.TypeURL() = %s; want %s", kt, testutil.XChaCha20Poly1305TypeURL)
	}
}

func genInvalidXChaCha20Poly1305Keys() []*xcppb.XChaCha20Poly1305Key {
	return []*xcppb.XChaCha20Poly1305Key{
		// Bad key size.
		&xcppb.XChaCha20Poly1305Key{
			Version:  testutil.XChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(17),
		},
		&xcppb.XChaCha20Poly1305Key{
			Version:  testutil.XChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(25),
		},
		&xcppb.XChaCha20Poly1305Key{
			Version:  testutil.XChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(33),
		},
		// Bad version.
		&xcppb.XChaCha20Poly1305Key{
			Version:  testutil.XChaCha20Poly1305KeyVersion + 1,
			KeyValue: random.GetRandomBytes(chacha20poly1305.KeySize),
		},
	}
}

func validateXChaCha20Poly1305Primitive(p interface{}, key *xcppb.XChaCha20Poly1305Key) error {
	cipher := p.(*subtle.XChaCha20Poly1305)
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

func validateXChaCha20Poly1305Key(key *xcppb.XChaCha20Poly1305Key) error {
	if key.Version != testutil.XChaCha20Poly1305KeyVersion {
		return fmt.Errorf("incorrect key version: keyVersion != %d", testutil.XChaCha20Poly1305KeyVersion)
	}
	if uint32(len(key.KeyValue)) != chacha20poly1305.KeySize {
		return fmt.Errorf("incorrect key size: keySize != %d", chacha20poly1305.KeySize)
	}

	// Try to encrypt and decrypt.
	p, err := subtle.NewXChaCha20Poly1305(key.KeyValue)
	if err != nil {
		return fmt.Errorf("invalid key: %v", key.KeyValue)
	}
	return validateXChaCha20Poly1305Primitive(p, key)
}
