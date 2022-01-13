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
	"strings"
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
	mode   uint8
	kemID  uint16
	kdfID  uint16
	aeadID uint16
	info   []byte
	// TODO(b/201070904): Rename to Pub/PrivKey.
	senderPublicKey     []byte
	senderPrivateKey    []byte
	recipientPublicKey  []byte
	recipientPrivateKey []byte
	encapsulatedKey     []byte
	sharedSecret        []byte
	keyScheduleCtx      []byte
	secret              []byte
	key                 []byte
	baseNonce           []byte
}

func TestX25519HpkeKemEncapsulateSucceeds(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	for _, test := range aeadTests {
		t.Run(test.name, func(t *testing.T) {
			key := id{baseMode, x25519HkdfSha256, hkdfSha256, test.aeadID}
			vec, ok := vecs[key]
			if !ok {
				t.Fatalf("failed to find vector %v", key)
			}

			kem := newX25519HpkeKem(sha256)
			generatePrivateKey = func() ([]byte, error) {
				return vec.senderPrivateKey, nil
			}

			secret, enc, err := kem.encapsulate(vec.recipientPublicKey)
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

func TestX25519HpkeKemEncapsulateFailsWithBadMAC(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem := newX25519HpkeKem("BadMac")
	_, _, err := kem.encapsulate(vec.recipientPublicKey)
	if err == nil {
		t.Error("kem.encapsulate: got success, want err")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("kem.encapsulate: got err %q, want %q", err, "MAC algorithm BadMac is not supported")
	}
}

func TestX25519HpkeKemEncapsulateFailsWithBadRecipientPublicKey(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem := newX25519HpkeKem(sha256)
	badRecipientPublicKey := append(vec.recipientPublicKey, []byte("hello")...)
	if _, _, err := kem.encapsulate(badRecipientPublicKey); err == nil {
		t.Error("kem.encapsulate: got success, want err")
	}
}

func TestX25519HpkeKemEncapsulateFailsWithBadSenderPrivateKey(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem := newX25519HpkeKem(sha256)
	publicFromPrivateX25519 = func(privKey []byte) ([]byte, error) {
		return nil, errors.New("failed to compute public key")
	}
	if _, _, err := kem.encapsulate(vec.recipientPublicKey); err == nil {
		t.Error("kem.encapsulate: got success, want err")
	}
	publicFromPrivateX25519 = subtle.PublicFromPrivateX25519
}

func TestX25519HpkeKemDecapsulateSucceeds(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	for _, test := range aeadTests {
		t.Run(test.name, func(t *testing.T) {
			key := id{baseMode, x25519HkdfSha256, hkdfSha256, test.aeadID}
			vec, ok := vecs[key]
			if !ok {
				t.Fatalf("failed to find vector %v", key)
			}

			kem := newX25519HpkeKem(sha256)
			secret, err := kem.decapsulate(vec.encapsulatedKey, vec.recipientPrivateKey)
			if err != nil {
				t.Errorf("kem.decapsulate for vector %v: got err %q, want success", key, err)
			}
			if !bytes.Equal(secret, vec.sharedSecret) {
				t.Errorf("kem.decapsulate for vector %v: got shared secret %v, want %v", key, secret, vec.sharedSecret)
			}
		})
	}
}

func TestX25519HpkeKemDecapsulateFailsWithBadMAC(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem := newX25519HpkeKem("BadMac")
	_, err := kem.decapsulate(vec.encapsulatedKey, vec.recipientPrivateKey)
	if err == nil {
		t.Error("kem.decapsulate: got success, want err")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("kem.decapsulate: got err %q, want %q", err, "MAC algorithm BadMac is not supported")
	}
}

func TestX25519HpkeKemDecapsulateFailsWithBadEncapsulatedKey(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem := newX25519HpkeKem(sha256)
	badEncapsulatedKey := append(vec.encapsulatedKey, []byte("hello")...)
	if _, err := kem.decapsulate(badEncapsulatedKey, vec.recipientPrivateKey); err == nil {
		t.Error("kem.decapsulate: got success, want err")
	}
}

func TestX25519HpkeKemDecapsulateFailsWithBadRecipientPrivateKey(t *testing.T) {
	vecs := x25519HkdfSha256BaseModeTestVectors(t)
	vec := defaultVector(t, vecs)
	kem := newX25519HpkeKem(sha256)
	badRecipientPrivateKey := append(vec.recipientPrivateKey, []byte("hello")...)
	if _, err := kem.decapsulate(vec.encapsulatedKey, badRecipientPrivateKey); err == nil {
		t.Error("kem.decapsulate: got success, want err")
	}
}

func TestX25519HpkeKemGetKEMIDSucceeds(t *testing.T) {
	kem := newX25519HpkeKem(sha256)
	kemID, err := kem.kemID()
	if err != nil {
		t.Fatalf("kem.kemID: got %v, want success", err)
	}
	if kemID != x25519HkdfSha256 {
		t.Errorf("kem.kemID: got %d, want %d", kemID, x25519HkdfSha256)
	}
}

func TestX25519HpkeKemGetKEMIDFailsWithBadMAC(t *testing.T) {
	kem := newX25519HpkeKem("BadMac")
	kemID, err := kem.kemID()
	if err == nil {
		t.Errorf("kem.kemID: got %d, want error", kemID)
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
		Mode                uint8  `json:"mode"`
		KEMID               uint16 `json:"kem_id"`
		KDFID               uint16 `json:"kdf_id"`
		AEADID              uint16 `json:"aead_id"`
		Info                string `json:"info"`
		SenderPublicKey     string `json:"pkEm"`
		SenderPrivateKey    string `json:"skEm"`
		RecipientPublicKey  string `json:"pkRm"`
		RecipientPrivateKey string `json:"skRm"`
		EncapsulatedKey     string `json:"enc"`
		SharedSecret        string `json:"shared_secret"`
		KeyScheduleCtx      string `json:"key_schedule_context"`
		Secret              string `json:"secret"`
		Key                 string `json:"key"`
		BaseNonce           string `json:"base_nonce"`
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
		if val.senderPublicKey, err = hex.DecodeString(v.SenderPublicKey); err != nil {
			t.Errorf("hex.DecodeString(SenderPublicKey) in vector %v failed", key)
		}
		if val.senderPrivateKey, err = hex.DecodeString(v.SenderPrivateKey); err != nil {
			t.Errorf("hex.DecodeString(SenderPrivateKey) in vector %v failed", key)
		}
		if val.recipientPublicKey, err = hex.DecodeString(v.RecipientPublicKey); err != nil {
			t.Errorf("hex.DecodeString(RecipientPublicKey) in vector %v failed", key)
		}
		if val.recipientPrivateKey, err = hex.DecodeString(v.RecipientPrivateKey); err != nil {
			t.Errorf("hex.DecodeString(RecipientPrivateKey) in vector %v failed", key)
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
