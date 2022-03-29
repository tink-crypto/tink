// Copyright 2021 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

package hpke

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/subtle"
)

// TODO(b/201070904): Write tests using internetDraftVector.
func TestX25519KEMEncapsulateBoringSSLVectors(t *testing.T) {
	i := 0
	vecs := baseModeX25519HKDFSHA256Vectors(t)
	for key, vec := range vecs {
		if key.mode != baseMode ||
			key.kemID != x25519HKDFSHA256 ||
			key.kdfID != hkdfSHA256 ||
			(key.aeadID != aes128GCM && key.aeadID != aes256GCM && key.aeadID != chaCha20Poly1305) {
			continue
		}

		i++
		t.Run(fmt.Sprintf("%d", key.id), func(t *testing.T) {
			kem, err := newKEM(x25519HKDFSHA256)
			if err != nil {
				t.Fatal(err)
			}
			x25519KEMGeneratePrivateKey = func() ([]byte, error) {
				return vec.senderPrivKey, nil
			}

			secret, enc, err := kem.encapsulate(vec.recipientPubKey)
			if err != nil {
				t.Errorf("encapsulate for vector %v: got err %q, want success", key, err)
			}
			if !bytes.Equal(secret, vec.sharedSecret) {
				t.Errorf("encapsulate for vector %v: got shared secret %v, want %v", key, secret, vec.sharedSecret)
			}
			if !bytes.Equal(enc, vec.encapsulatedKey) {
				t.Errorf("encapsulate for vector %v: got encapsulated key %v, want %v", key, enc, vec.encapsulatedKey)
			}
		})
	}
	x25519KEMGeneratePrivateKey = subtle.GeneratePrivateKeyX25519
	if i < 2 {
		t.Errorf("number of vectors tested = %d, want > %d", i, 2)
	}
}

func TestX25519KEMEncapsulateBadRecipientPubKey(t *testing.T) {
	_, v := internetDraftVector(t)
	kem, err := newKEM(x25519HKDFSHA256)
	if err != nil {
		t.Fatal(err)
	}
	badRecipientPubKey := append(v.recipientPubKey, []byte("hello")...)
	if _, _, err := kem.encapsulate(badRecipientPubKey); err == nil {
		t.Error("encapsulate: got success, want err")
	}
}

func TestX25519KEMEncapsulateBadSenderPrivKey(t *testing.T) {
	_, v := internetDraftVector(t)
	kem, err := newKEM(x25519HKDFSHA256)
	if err != nil {
		t.Fatal(err)
	}

	x25519KEMPublicFromPrivate = func(privKey []byte) ([]byte, error) {
		return nil, errors.New("failed to compute public key")
	}
	if _, _, err := kem.encapsulate(v.recipientPubKey); err == nil {
		t.Error("encapsulate: got success, want err")
	}
	x25519KEMPublicFromPrivate = subtle.PublicFromPrivateX25519
}

func TestX25519KEMDecapsulateBoringSSLVectors(t *testing.T) {
	i := 0
	vecs := baseModeX25519HKDFSHA256Vectors(t)
	for key, vec := range vecs {
		if key.mode != baseMode ||
			key.kemID != x25519HKDFSHA256 ||
			key.kdfID != hkdfSHA256 ||
			(key.aeadID != aes128GCM && key.aeadID != aes256GCM && key.aeadID != chaCha20Poly1305) {
			continue
		}

		i++
		t.Run(fmt.Sprintf("%d", key.id), func(t *testing.T) {
			kem, err := newKEM(x25519HKDFSHA256)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := kem.decapsulate(vec.encapsulatedKey, vec.recipientPrivKey)
			if err != nil {
				t.Errorf("decapsulate for vector %v: got err %q, want success", key, err)
			}
			if !bytes.Equal(secret, vec.sharedSecret) {
				t.Errorf("decapsulate for vector %v: got shared secret %v, want %v", key, secret, vec.sharedSecret)
			}
		})
	}
	if i < 2 {
		t.Errorf("number of vectors tested = %d, want > %d", i, 2)
	}
}

// TestX25519KEMDecapsulateEncapsulatedKeyPrefixesLargerSlice checks--if the
// encapsulated key is part of a larger slice, as in HPKE Encrypt
// https://github.com/google/tink/blob/619b6c1bb1f8573ca56de50cfc6ba23d355670db/go/hybrid/hpke/encrypt.go#L61
// --that decapsulate does not modify the larger slice.
func TestX25519KEMDecapsulateEncapsulatedKeyPrefixesLargerSlice(t *testing.T) {
	_, v := internetDraftVector(t)
	kem, err := newKEM(x25519HKDFSHA256)
	if err != nil {
		t.Fatal(err)
	}

	largerSlice := make([]byte, 3*len(v.encapsulatedKey))
	suffix := largerSlice[len(v.encapsulatedKey):]
	zeroedSlice := make([]byte, len(suffix))
	if !bytes.Equal(suffix, zeroedSlice) {
		t.Errorf("suffix: got %x, want %x", suffix, zeroedSlice)
	}

	copy(largerSlice, v.encapsulatedKey)
	if !bytes.Equal(suffix, zeroedSlice) {
		t.Errorf("suffix: got %x, want %x", suffix, zeroedSlice)
	}

	encapsulatedKey := largerSlice[:len(v.encapsulatedKey)]
	if _, err := kem.decapsulate(encapsulatedKey, v.recipientPrivKey); err != nil {
		t.Errorf("decapsulate: got err %q, want success", err)
	}
	if !bytes.Equal(suffix, zeroedSlice) {
		t.Errorf("suffix: got %x, want %x", suffix, zeroedSlice)
	}
}

func TestX25519KEMDecapsulateBadEncapsulatedKey(t *testing.T) {
	_, v := internetDraftVector(t)
	kem, err := newKEM(x25519HKDFSHA256)
	if err != nil {
		t.Fatal(err)
	}
	badEncapsulatedKey := append(v.encapsulatedKey, []byte("hello")...)
	if _, err := kem.decapsulate(badEncapsulatedKey, v.recipientPrivKey); err == nil {
		t.Error("decapsulate: got success, want err")
	}
}

func TestX25519KEMDecapsulateBadRecipientPrivKey(t *testing.T) {
	_, v := internetDraftVector(t)
	kem, err := newKEM(x25519HKDFSHA256)
	if err != nil {
		t.Fatal(err)
	}
	badRecipientPrivKey := append(v.recipientPrivKey, []byte("hello")...)
	if _, err := kem.decapsulate(v.encapsulatedKey, badRecipientPrivKey); err == nil {
		t.Error("decapsulate: got success, want err")
	}
}

func TestX25519KEMEncapsulatedKeyLength(t *testing.T) {
	kem, err := newKEM(x25519HKDFSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if kem.encapsulatedKeyLength() != 32 {
		t.Errorf("encapsulatedKeyLength: got %d, want 32", kem.encapsulatedKeyLength())
	}
}
