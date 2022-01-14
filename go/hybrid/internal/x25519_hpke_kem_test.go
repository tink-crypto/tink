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

package internal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/tink/go/subtle"
)

var aeadTests = []struct {
	name   string
	aeadID uint16
}{
	{"AES128GCM", aes128GCM},
	{"AES256GCM", aes256GCM},
	{"ChaCha20Poly1305", chaCha20Poly1305},
	{"ExportOnlyAEAD", 0xFFFF},
}

type id struct {
	mode   uint8
	kemID  uint16
	kdfID  uint16
	aeadID uint16
}

// TODO(b/201070904): Separate into own package.
type vector struct {
	mode             uint8
	kemID            uint16
	kdfID            uint16
	aeadID           uint16
	info             []byte
	senderPubKey     []byte
	senderPrivKey    []byte
	recipientPubKey  []byte
	recipientPrivKey []byte
	encapsulatedKey  []byte
	sharedSecret     []byte
	keyScheduleCtx   []byte
	secret           []byte
	key              []byte
	baseNonce        []byte
}

func TestX25519HpkeKemWithBadMacAlgFails(t *testing.T) {
	if _, err := newX25519HpkeKem("BadMac"); err == nil {
		t.Error("newX25519HpkeKem(BadMac): got success, want error")
	}
}

// TODO(b/201070904): Add tests using hard-coded I-D vector.
func TestX25519HpkeKemEncapsulateWithBoringSslVectors(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	for _, test := range aeadTests {
		t.Run(test.name, func(t *testing.T) {
			key := id{baseMode, x25519HkdfSha256, hkdfSha256, test.aeadID}
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
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem, err := newX25519HpkeKem(sha256)
	if err != nil {
		t.Fatal(err)
	}
	badRecipientPubKey := append(vec.recipientPubKey, []byte("hello")...)
	if _, _, err := kem.encapsulate(badRecipientPubKey); err == nil {
		t.Error("kem.encapsulate: got success, want err")
	}
}

func TestX25519HpkeKemEncapsulateWithBadSenderPrivKeyFails(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem, err := newX25519HpkeKem(sha256)
	if err != nil {
		t.Fatal(err)
	}
	publicFromPrivateX25519 = func(privKey []byte) ([]byte, error) {
		return nil, errors.New("failed to compute public key")
	}
	if _, _, err := kem.encapsulate(vec.recipientPubKey); err == nil {
		t.Error("kem.encapsulate: got success, want err")
	}
	publicFromPrivateX25519 = subtle.PublicFromPrivateX25519
}

func TestX25519HpkeKemDecapsulateWithBoringSslVectors(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	for _, test := range aeadTests {
		t.Run(test.name, func(t *testing.T) {
			key := id{baseMode, x25519HkdfSha256, hkdfSha256, test.aeadID}
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
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem, err := newX25519HpkeKem(sha256)
	if err != nil {
		t.Fatal(err)
	}
	badEncapsulatedKey := append(vec.encapsulatedKey, []byte("hello")...)
	if _, err := kem.decapsulate(badEncapsulatedKey, vec.recipientPrivKey); err == nil {
		t.Error("kem.decapsulate: got success, want err")
	}
}

func TestX25519HpkeKemDecapsulateWithBadRecipientPrivKeyFails(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem, err := newX25519HpkeKem(sha256)
	if err != nil {
		t.Fatal(err)
	}
	badRecipientPrivKey := append(vec.recipientPrivKey, []byte("hello")...)
	if _, err := kem.decapsulate(vec.encapsulatedKey, badRecipientPrivKey); err == nil {
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

// TODO(b/201070904): Separate into own package.
func x25519HkdfSha256BaseModeTestVectors(t *testing.T) map[id]vector {
	t.Helper()

	// TEST_SRCDIR is only defined for Blaze/Bazel builds. For details, see
	// http://google3/third_party/tink/go/testutil/wycheproofutil.go;l=32;rcl=395431754.
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not found")
	}
	path := filepath.Join(srcDir, os.Getenv("TEST_WORKSPACE"), "/hybrid/internal/testdata/boringssl_hpke_test_vectors.json")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	var vecs []struct {
		Mode             uint8  `json:"mode"`
		KEMID            uint16 `json:"kem_id"`
		KDFID            uint16 `json:"kdf_id"`
		AEADID           uint16 `json:"aead_id"`
		Info             string `json:"info"`
		SenderPubKey     string `json:"pkEm"`
		SenderPrivKey    string `json:"skEm"`
		RecipientPubKey  string `json:"pkRm"`
		RecipientPrivKey string `json:"skRm"`
		EncapsulatedKey  string `json:"enc"`
		SharedSecret     string `json:"shared_secret"`
		KeyScheduleCtx   string `json:"key_schedule_context"`
		Secret           string `json:"secret"`
		Key              string `json:"key"`
		BaseNonce        string `json:"base_nonce"`
	}
	parser := json.NewDecoder(f)
	if err := parser.Decode(&vecs); err != nil {
		t.Fatal(err)
	}

	m := make(map[id]vector)
	for _, v := range vecs {
		if v.Mode != baseMode || v.KEMID != x25519HkdfSha256 {
			continue
		}

		key := id{
			mode:   v.Mode,
			kemID:  v.KEMID,
			kdfID:  v.KDFID,
			aeadID: v.AEADID,
		}
		var val vector
		if val.info, err = hex.DecodeString(v.Info); err != nil {
			t.Errorf("hex.DecodeString(Info) in vector %v failed", key)
		}
		if val.senderPubKey, err = hex.DecodeString(v.SenderPubKey); err != nil {
			t.Errorf("hex.DecodeString(SenderPubKey) in vector %v failed", key)
		}
		if val.senderPrivKey, err = hex.DecodeString(v.SenderPrivKey); err != nil {
			t.Errorf("hex.DecodeString(SenderPrivKey) in vector %v failed", key)
		}
		if val.recipientPubKey, err = hex.DecodeString(v.RecipientPubKey); err != nil {
			t.Errorf("hex.DecodeString(RecipientPubKey) in vector %v failed", key)
		}
		if val.recipientPrivKey, err = hex.DecodeString(v.RecipientPrivKey); err != nil {
			t.Errorf("hex.DecodeString(RecipientPrivKey) in vector %v failed", key)
		}
		if val.encapsulatedKey, err = hex.DecodeString(v.EncapsulatedKey); err != nil {
			t.Errorf("hex.DecodeString(EncapsulatedKey) in vector %v failed", key)
		}
		if val.sharedSecret, err = hex.DecodeString(v.SharedSecret); err != nil {
			t.Errorf("hex.DecodeString(SharedSecret) in vector %v failed", key)
		}
		if val.keyScheduleCtx, err = hex.DecodeString(v.KeyScheduleCtx); err != nil {
			t.Errorf("hex.DecodeString(KeyScheduleCtx) in vector %v failed", key)
		}
		if val.secret, err = hex.DecodeString(v.Secret); err != nil {
			t.Errorf("hex.DecodeString(Secret) in vector %v failed", key)
		}
		if val.key, err = hex.DecodeString(v.Key); err != nil {
			t.Errorf("hex.DecodeString(Key) in vector %v failed", key)
		}
		if val.baseNonce, err = hex.DecodeString(v.BaseNonce); err != nil {
			t.Errorf("hex.DecodeString(BaseNonce) in vector %v failed", key)
		}
		m[key] = val
	}

	return m
}

// TODO(b/201070904): Replace with hard-coded vector, see
// https://critique.corp.google.com/cl/413830047/depot/google3/third_party/tink/go/hybrid/internal/hkdf_hpke_kdf_test.go?version=s10#31.
func defaultVector(t *testing.T, vecs map[id]vector) vector {
	t.Helper()
	key := id{baseMode, x25519HkdfSha256, hkdfSha256, aes128GCM}
	vec, ok := vecs[key]
	if !ok {
		t.Errorf("failed to find vector %v", key)
	}
	return vec
}
