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

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/chacha20poly1305"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/subtle/random"

	subteaead "github.com/google/tink/go/subtle/aead"
	cppb "github.com/google/tink/proto/chacha20_poly1305_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestNewChaCha20Poly1305KeyManager(t *testing.T) {
	km := aead.NewChaCha20Poly1305KeyManager()
	if km == nil {
		t.Errorf("NewChaCha20Poly1305KeyManager() returns nil")
	}
}

func TestChaCha20Poly1305GetPrimitive(t *testing.T) {
	km := aead.NewChaCha20Poly1305KeyManager()
	key := km.NewChaCha20Poly1305Key()
	p, err := km.GetPrimitiveFromKey(key)
	if err != nil {
		t.Errorf("km.GetPrimitiveFromKey(%v) = %v; want nil", key, err)
	}
	if err := validateChaCha20Poly1305Primitive(p, key); err != nil {
		t.Errorf("validateChaCha20Poly1305Primitive(p, key) = %v; want nil", err)
	}

	serializedKey, _ := proto.Marshal(key)
	p, err = km.GetPrimitiveFromSerializedKey(serializedKey)
	if err != nil {
		t.Errorf("km.GetPrimitiveFromSerializedKey(%v) = %v; want nil", serializedKey, err)
	}
	if err := validateChaCha20Poly1305Primitive(p, key); err != nil {
		t.Errorf("validateChaCha20Poly1305Primitive(p, key) = %v; want nil", err)
	}
}

func TestChaCha20Poly1305GetPrimitiveWithInvalidKeys(t *testing.T) {
	km := aead.NewChaCha20Poly1305KeyManager()
	invalidKeys := genInvalidChaCha20Poly1305Keys()
	for _, key := range invalidKeys {
		if _, err := km.GetPrimitiveFromKey(key); err == nil {
			t.Errorf("km.GetPrimitiveFromKey(%v) = _, nil; want _, err", key)
		}
		serializedKey, _ := proto.Marshal(key)
		if _, err := km.GetPrimitiveFromSerializedKey(serializedKey); err == nil {
			t.Errorf("km.GetPrimitiveFromSerializedKey(%v) = _, nil; want _, err", serializedKey)
		}
	}
}

func TestChaCha20Poly1305NewKeyFromSerializedKeyFormat(t *testing.T) {
	km := aead.NewChaCha20Poly1305KeyManager()
	m, err := km.NewKeyFromSerializedKeyFormat(nil)
	if err != nil {
		t.Errorf("km.NewKeyFromSerializedKeyFormat(nil) = _, %v; want _, nil", err)
	}
	key, _ := m.(*cppb.ChaCha20Poly1305Key)
	if err := validateChaCha20Poly1305Key(key); err != nil {
		t.Errorf("validateChaCha20Poly1305Key(%v) = %v; want nil", key, err)
	}
}

func TestChaCha20Poly1305NewKeyFromKeyFormat(t *testing.T) {
	km := aead.NewChaCha20Poly1305KeyManager()
	m, err := km.NewKeyFromKeyFormat(nil)
	if err != nil {
		t.Errorf("km.NewKeyFromKeyFormat(nil) = _, %v; want _, nil", err)
	}
	key, _ := m.(*cppb.ChaCha20Poly1305Key)
	if err := validateChaCha20Poly1305Key(key); err != nil {
		t.Errorf("validateChaCha20Poly1305Key(%v) = %v; want nil", key, err)
	}
}

func TestNewChaCha20Poly1305Key(t *testing.T) {
	km := aead.NewChaCha20Poly1305KeyManager()
	key := km.NewChaCha20Poly1305Key()
	if err := validateChaCha20Poly1305Key(key); err != nil {
		t.Errorf("validateChaCha20Poly1305Key(%v) = %v; want nil", key, err)
	}
}

func TestChaCha20Poly1305NewKeyData(t *testing.T) {
	km := aead.NewChaCha20Poly1305KeyManager()
	kd, err := km.NewKeyData(nil)
	if err != nil {
		t.Errorf("km.NewKeyData(nil) = _, %v; want _, nil", err)
	}
	if kd.TypeUrl != aead.ChaCha20Poly1305TypeURL {
		t.Errorf("TypeUrl: %v != %v", kd.TypeUrl, aead.ChaCha20Poly1305TypeURL)
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
	km := aead.NewChaCha20Poly1305KeyManager()
	if !km.DoesSupport(aead.ChaCha20Poly1305TypeURL) {
		t.Errorf("ChaCha20Poly1305KeyManager must support %s", aead.ChaCha20Poly1305TypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("ChaCha20Poly1305KeyManager must only support %s", aead.ChaCha20Poly1305TypeURL)
	}
}

func TestChaCha20Poly1305GetKeyType(t *testing.T) {
	km := aead.NewChaCha20Poly1305KeyManager()
	if kt := km.GetKeyType(); kt != aead.ChaCha20Poly1305TypeURL {
		t.Errorf("km.GetKeyType() = %s; want %s", kt, aead.ChaCha20Poly1305TypeURL)
	}
}

func genInvalidChaCha20Poly1305Keys() []*cppb.ChaCha20Poly1305Key {
	return []*cppb.ChaCha20Poly1305Key{
		// Bad key size.
		&cppb.ChaCha20Poly1305Key{
			Version:  aead.ChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(17),
		},
		&cppb.ChaCha20Poly1305Key{
			Version:  aead.ChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(25),
		},
		&cppb.ChaCha20Poly1305Key{
			Version:  aead.ChaCha20Poly1305KeyVersion,
			KeyValue: random.GetRandomBytes(33),
		},
		// Bad version.
		&cppb.ChaCha20Poly1305Key{
			Version:  aead.ChaCha20Poly1305KeyVersion + 1,
			KeyValue: random.GetRandomBytes(chacha20poly1305.KeySize),
		},
	}
}

func validateChaCha20Poly1305Primitive(p interface{}, key *cppb.ChaCha20Poly1305Key) error {
	cipher := p.(*subteaead.ChaCha20Poly1305)
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
	if key.Version != aead.ChaCha20Poly1305KeyVersion {
		return fmt.Errorf("incorrect key version: keyVersion != %d", aead.ChaCha20Poly1305KeyVersion)
	}
	if uint32(len(key.KeyValue)) != chacha20poly1305.KeySize {
		return fmt.Errorf("incorrect key size: keySize != %d", chacha20poly1305.KeySize)
	}

	// Try to encrypt and decrypt.
	p, err := subteaead.NewChaCha20Poly1305(key.KeyValue)
	if err != nil {
		return fmt.Errorf("invalid key: %v", key.KeyValue)
	}
	return validateChaCha20Poly1305Primitive(p, key)
}
