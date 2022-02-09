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
	"testing"

	"github.com/google/tink/go/subtle"
)

func TestX25519HpkeKemWithBadMacAlgFails(t *testing.T) {
	if _, err := newX25519HpkeKem("BadMac"); err == nil {
		t.Error("newX25519HpkeKem(BadMac): got success, want error")
	}
}

// TODO(b/201070904): Write tests using hpkeInternetDraftTestVector.
func TestX25519HpkeKemEncapsulateWithBoringSslVectors(t *testing.T) {
	vecs := hpkeX25519HkdfSha256BaseModeTestVectors(t)
	for _, test := range hpkeAeadIds {
		t.Run(test.name, func(t *testing.T) {
			key := hpkeID{baseMode, x25519HkdfSha256, hkdfSha256, test.aeadID}
			vec, ok := vecs[key]
			if !ok {
				t.Fatalf("failed to find vector %v", key)
			}

			kem, err := newX25519HpkeKem(sha256)
			if err != nil {
				t.Fatal(err)
			}
			generatePrivateKey = func() ([]byte, error) {
				return vec.senderPrivKey, nil
			}

			secret, enc, err := kem.encapsulate(vec.recipientPubKey)
			if err != nil {
				t.Errorf("kem.encapsulate for vector %v: got err %q, want success", key, err)
			}
			if !bytes.Equal(secret, vec.sharedSecret) {
				t.Errorf("kem.encapsulate for vector %v: got shared secret %v, want %v", key, secret, vec.sharedSecret)
			}
			if !bytes.Equal(enc, vec.encapsulatedKey) {
				t.Errorf("kem.encapsulate for vector %v: got encapsulated key %v, want %v", key, enc, vec.encapsulatedKey)
			}
		})
	}
	generatePrivateKey = subtle.GeneratePrivateKeyX25519
}

func TestX25519HpkeKemEncapsulateWithBadRecipientPubKeyFails(t *testing.T) {
	_, v, err := hpkeInternetDraftTestVector(t)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := newX25519HpkeKem(sha256)
	if err != nil {
		t.Fatal(err)
	}
	badRecipientPubKey := append(v.recipientPubKey, []byte("hello")...)
	if _, _, err := kem.encapsulate(badRecipientPubKey); err == nil {
		t.Error("kem.encapsulate: got success, want err")
	}
}

func TestX25519HpkeKemEncapsulateWithBadSenderPrivKeyFails(t *testing.T) {
	_, v, err := hpkeInternetDraftTestVector(t)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := newX25519HpkeKem(sha256)
	if err != nil {
		t.Fatal(err)
	}
	publicFromPrivateX25519 = func(privKey []byte) ([]byte, error) {
		return nil, errors.New("failed to compute public key")
	}
	if _, _, err := kem.encapsulate(v.recipientPubKey); err == nil {
		t.Error("kem.encapsulate: got success, want err")
	}
	publicFromPrivateX25519 = subtle.PublicFromPrivateX25519
}

func TestX25519HpkeKemDecapsulateWithBoringSslVectors(t *testing.T) {
	vecs := hpkeX25519HkdfSha256BaseModeTestVectors(t)
	for _, test := range hpkeAeadIds {
		t.Run(test.name, func(t *testing.T) {
			key := hpkeID{baseMode, x25519HkdfSha256, hkdfSha256, test.aeadID}
			vec, ok := vecs[key]
			if !ok {
				t.Fatalf("failed to find vector %v", key)
			}

			kem, err := newX25519HpkeKem(sha256)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := kem.decapsulate(vec.encapsulatedKey, vec.recipientPrivKey)
			if err != nil {
				t.Errorf("kem.decapsulate for vector %v: got err %q, want success", key, err)
			}
			if !bytes.Equal(secret, vec.sharedSecret) {
				t.Errorf("kem.decapsulate for vector %v: got shared secret %v, want %v", key, secret, vec.sharedSecret)
			}
		})
	}
}

func TestX25519HpkeKemDecapsulateWithBadEncapsulatedKeyFails(t *testing.T) {
	_, v, err := hpkeInternetDraftTestVector(t)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := newX25519HpkeKem(sha256)
	if err != nil {
		t.Fatal(err)
	}
	badEncapsulatedKey := append(v.encapsulatedKey, []byte("hello")...)
	if _, err := kem.decapsulate(badEncapsulatedKey, v.recipientPrivKey); err == nil {
		t.Error("kem.decapsulate: got success, want err")
	}
}

func TestX25519HpkeKemDecapsulateWithBadRecipientPrivKeyFails(t *testing.T) {
	_, v, err := hpkeInternetDraftTestVector(t)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := newX25519HpkeKem(sha256)
	if err != nil {
		t.Fatal(err)
	}
	badRecipientPrivKey := append(v.recipientPrivKey, []byte("hello")...)
	if _, err := kem.decapsulate(v.encapsulatedKey, badRecipientPrivKey); err == nil {
		t.Error("kem.decapsulate: got success, want err")
	}
}

func TestX25519HpkeKemKemId(t *testing.T) {
	kem, err := newX25519HpkeKem(sha256)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := kem.kemID(), x25519HkdfSha256; got != want {
		t.Errorf("kem.kemID: got %d, want %d", got, want)
	}
}
