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
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"

	"github.com/google/tink/go/aead/subtle"
	tpb "github.com/google/tink/go/proto/tink_go_proto"
	xpb "github.com/google/tink/go/proto/xchacha20_poly1305_go_proto"
)

func TestXChaCha20Poly1305GetPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("cannot obtain XChaCha20Poly1305 key manager: %s", err)
	}
	m, err := km.NewKey(nil)
	if err != nil {
		t.Fatalf("km.NewKey(nil) err = %q, want nil", err)
	}
	key, ok := m.(*xpb.XChaCha20Poly1305Key)
	if !ok {
		t.Fatal("m is not a *xpb.XChaCha20Poly1305Key")
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
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
	invalidKeys := []*xpb.XChaCha20Poly1305Key{
		// Bad key size.
		&xpb.XChaCha20Poly1305Key{
			Version:  testutil.XChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(17),
		},
		&xpb.XChaCha20Poly1305Key{
			Version:  testutil.XChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(25),
		},
		&xpb.XChaCha20Poly1305Key{
			Version:  testutil.XChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(33),
		},
		// Bad version.
		&xpb.XChaCha20Poly1305Key{
			Version:  testutil.XChaCha20Poly1305KeyVersion + 1,
			KeyValue: random.GetRandomBytes(chacha20poly1305.KeySize),
		},
	}
	for _, key := range invalidKeys {
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
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
	key, ok := m.(*xpb.XChaCha20Poly1305Key)
	if !ok {
		t.Errorf("m is not a *xpb.XChaCha20Poly1305Key")
	}
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
	if kd.KeyMaterialType != tpb.KeyData_SYMMETRIC {
		t.Errorf("KeyMaterialType: %v != SYMMETRIC", kd.KeyMaterialType)
	}
	key := new(xpb.XChaCha20Poly1305Key)
	if err := proto.Unmarshal(kd.Value, key); err != nil {
		t.Errorf("proto.Unmarshal(%v, key) = %v; want nil", kd.Value, err)
	}
	if err := validateXChaCha20Poly1305Key(key); err != nil {
		t.Errorf("validateXChaCha20Poly1305Key(%v) = %v; want nil", key, err)
	}
	p, err := registry.PrimitiveFromKeyData(kd)
	if err != nil {
		t.Errorf("registry.PrimitiveFromKeyData(kd) err = %v, want nil", err)
	}
	_, ok := p.(*subtle.XChaCha20Poly1305)
	if !ok {
		t.Error("registry.PrimitiveFromKeyData(kd) did not return a XChaCha20Poly1305 primitive")
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

func TestXChaCha20Poly1305KeyMaterialType(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.XChaCha20Poly1305TypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	if got, want := keyManager.KeyMaterialType(), tpb.KeyData_SYMMETRIC; got != want {
		t.Errorf("KeyMaterialType() = %v, want %v", got, want)
	}
}

func TestXChaCha20Poly1305DeriveKey(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.XChaCha20Poly1305TypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat, err := proto.Marshal(&xpb.XChaCha20Poly1305KeyFormat{Version: 0})
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	for _, test := range []struct {
		name      string
		keyFormat []byte
	}{
		{
			// nil unmarshals to an empty proto, which implies version = 0.
			name:      "nil",
			keyFormat: nil,
		},
		{
			// An empty proto implies version = 0.
			name:      "empty",
			keyFormat: []byte{},
		},
		{
			name:      "specified",
			keyFormat: keyFormat,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rand := random.GetRandomBytes(chacha20poly1305.KeySize)
			buf := &bytes.Buffer{}
			buf.Write(rand) // never returns a non-nil error
			k, err := keyManager.DeriveKey(test.keyFormat, buf)
			if err != nil {
				t.Fatalf("keyManager.DeriveKey() err = %v, want nil", err)
			}
			key := k.(*xpb.XChaCha20Poly1305Key)
			if got, want := len(key.GetKeyValue()), chacha20poly1305.KeySize; got != want {
				t.Errorf("key length = %d, want %d", got, want)
			}
			if diff := cmp.Diff(key.GetKeyValue(), rand); diff != "" {
				t.Errorf("incorrect derived key: diff = %v", diff)
			}
		})
	}
}

func TestXChaCha20Poly1305DeriveKeyFailsWithInvalidKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.XChaCha20Poly1305TypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	invalidVersion, err := proto.Marshal(&xpb.XChaCha20Poly1305KeyFormat{Version: 10})
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
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
			name:      "invalid version",
			keyFormat: invalidVersion,
		},
		{
			name:      "invalid serialization",
			keyFormat: invalidSerialization,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			buf := bytes.NewBuffer(random.GetRandomBytes(chacha20poly1305.KeySize))
			if _, err := keyManager.DeriveKey(test.keyFormat, buf); err == nil {
				t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
			}
		})
	}
}

func TestXChaCha20Poly1305DeriveKeyFailsWithInsufficientRandomness(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.XChaCha20Poly1305TypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	keyFormat, err := proto.Marshal(&xpb.XChaCha20Poly1305KeyFormat{Version: 0})
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	{
		buf := bytes.NewBuffer(random.GetRandomBytes(chacha20poly1305.KeySize))
		if _, err := keyManager.DeriveKey(keyFormat, buf); err != nil {
			t.Errorf("keyManager.DeriveKey() err = %v, want nil", err)
		}
	}
	{
		insufficientBuf := bytes.NewBuffer(random.GetRandomBytes(chacha20poly1305.KeySize - 1))
		if _, err := keyManager.DeriveKey(keyFormat, insufficientBuf); err == nil {
			t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
		}
	}
}

func validateXChaCha20Poly1305Primitive(p any, key *xpb.XChaCha20Poly1305Key) error {
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

func validateXChaCha20Poly1305Key(key *xpb.XChaCha20Poly1305Key) error {
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
