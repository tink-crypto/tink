// Copyright 2022 Google LLC
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
	"math/rand"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	pb "github.com/google/tink/go/proto/hpke_go_proto"
)

func TestNewEncryptDecryptUnknownKEM(t *testing.T) {
	params := validParams(t)
	params.Kem = pb.HpkeKem_KEM_UNKNOWN
	pubKey, privKey := pubPrivKeys(t, params)

	if _, err := NewEncrypt(pubKey); err == nil {
		t.Error("NewEncrypt(unknown KEM): got success, want err")
	}
	if _, err := NewDecrypt(privKey); err == nil {
		t.Error("NewDecrypt(unknown KEM): got success, want err")
	}
}

func TestNewEncryptDecryptUnknownKDF(t *testing.T) {
	params := validParams(t)
	params.Kdf = pb.HpkeKdf_KDF_UNKNOWN
	pubKey, privKey := pubPrivKeys(t, params)

	if _, err := NewEncrypt(pubKey); err == nil {
		t.Error("NewEncrypt(unknown KDF): got success, want err")
	}
	if _, err := NewDecrypt(privKey); err == nil {
		t.Error("NewDecrypt(unknown KDF): got success, want err")
	}
}

func TestNewEncryptDecryptUnknownAEAD(t *testing.T) {
	params := validParams(t)
	params.Aead = pb.HpkeAead_AEAD_UNKNOWN
	pubKey, privKey := pubPrivKeys(t, params)

	if _, err := NewEncrypt(pubKey); err == nil {
		t.Error("NewEncrypt(unknown AEAD): got success, want err")
	}
	if _, err := NewDecrypt(privKey); err == nil {
		t.Error("NewDecrypt(unknown AEAD): got success, want err")
	}
}

func TestNewEncryptDecryptMissingParams(t *testing.T) {
	pubKey, privKey := pubPrivKeys(t, nil)

	if _, err := NewEncrypt(pubKey); err == nil {
		t.Error("NewEncrypt(missing params): got success, want err")
	}
	if _, err := NewDecrypt(privKey); err == nil {
		t.Error("NewDecrypt(missing params): got success, want err")
	}
}

func TestNewEncryptMissingPubKeyBytes(t *testing.T) {
	pubKey, _ := pubPrivKeys(t, validParams(t))
	pubKey.PublicKey = nil
	if _, err := NewEncrypt(pubKey); err == nil {
		t.Error("NewEncrypt(nil pub key): got success, want err")
	}
	pubKey.PublicKey = []byte{}
	if _, err := NewEncrypt(pubKey); err == nil {
		t.Error("NewEncrypt(zero-length pub key): got success, want err")
	}
}

func TestNewDecryptMissingPrivKeyBytes(t *testing.T) {
	_, privKey := pubPrivKeys(t, validParams(t))
	privKey.PrivateKey = nil
	if _, err := NewDecrypt(privKey); err == nil {
		t.Error("NewDecrypt(nil priv key): got success, want err")
	}
	privKey.PrivateKey = []byte{}
	if _, err := NewDecrypt(privKey); err == nil {
		t.Error("NewDecrypt(zero-length priv key): got success, want err")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	aeadIDs := []pb.HpkeAead{pb.HpkeAead_AES_128_GCM, pb.HpkeAead_AES_256_GCM}
	for _, aeadID := range aeadIDs {
		params := &pb.HpkeParams{
			Kem:  pb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
			Kdf:  pb.HpkeKdf_HKDF_SHA256,
			Aead: aeadID,
		}
		pubKey, privKey := pubPrivKeys(t, params)

		enc, err := NewEncrypt(pubKey)
		if err != nil {
			t.Fatalf("NewEncrypt: err %q", err)
		}
		dec, err := NewDecrypt(privKey)
		if err != nil {
			t.Fatalf("NewDecrypt: err %q", err)
		}

		wantPT := random.GetRandomBytes(200)
		ctxInfo := random.GetRandomBytes(100)
		ct, err := enc.Encrypt(wantPT, ctxInfo)
		if err != nil {
			t.Fatalf("Encrypt: err %q", err)
		}
		gotPT, err := dec.Decrypt(ct, ctxInfo)
		if err != nil {
			t.Fatalf("Decrypt: err %q", err)
		}
		if !bytes.Equal(gotPT, wantPT) {
			t.Errorf("Decrypt: got %q, want %q", gotPT, wantPT)
		}
	}
}

func TestDecryptModifiedCiphertextOrContextInfo(t *testing.T) {
	pubKey, privKey := pubPrivKeys(t, validParams(t))
	enc, err := NewEncrypt(pubKey)
	if err != nil {
		t.Fatalf("NewEncrypt: err %q", err)
	}
	dec, err := NewDecrypt(privKey)
	if err != nil {
		t.Fatalf("NewDecrypt: err %q", err)
	}

	wantPT := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)
	ct, err := enc.Encrypt(wantPT, ctxInfo)
	if err != nil {
		t.Fatalf("Encrypt: err %q", err)
	}
	gotPT, err := dec.Decrypt(ct, ctxInfo)
	if err != nil {
		t.Fatalf("Decrypt: err %q", err)
	}
	if !bytes.Equal(gotPT, wantPT) {
		t.Errorf("Decrypt: got %q, want %q", gotPT, wantPT)
	}

	tests := []struct {
		name    string
		ct      []byte
		ctxInfo []byte
	}{
		{"extended ct", append(ct, []byte("hi there")...), ctxInfo},
		{"flip byte ct", flipRandByte(t, ct), ctxInfo},
		{"short ct", ct[:len(ct)-5], ctxInfo},
		{"empty ct", []byte{}, ctxInfo},
		{"extended ctxInfo", ct, append(ctxInfo, []byte("hi there")...)},
		{"flip byte ctxInfo", ct, flipRandByte(t, ctxInfo)},
		{"short ctxInfo", ct, ctxInfo[:len(ctxInfo)-5]},
		{"empty ctxInfo", ct, []byte{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := dec.Decrypt(test.ct, test.ctxInfo); err == nil {
				t.Error("Decrypt: got success, want err")
			}
		})
	}
}

func TestEncryptDecryptEmptyContextInfo(t *testing.T) {
	pubKey, privKey := pubPrivKeys(t, validParams(t))
	enc, err := NewEncrypt(pubKey)
	if err != nil {
		t.Fatalf("NewEncrypt: err %q", err)
	}
	dec, err := NewDecrypt(privKey)
	if err != nil {
		t.Fatalf("NewDecrypt: err %q", err)
	}

	wantPT := random.GetRandomBytes(200)
	ctxInfo := []byte{}
	ct, err := enc.Encrypt(wantPT, ctxInfo)
	if err != nil {
		t.Fatalf("Encrypt: err %q", err)
	}
	gotPT, err := dec.Decrypt(ct, ctxInfo)
	if err != nil {
		t.Fatalf("Decrypt: err %q", err)
	}
	if !bytes.Equal(gotPT, wantPT) {
		t.Errorf("Decrypt: got %q, want %q", gotPT, wantPT)
	}
}

// TestDecryptEncapsulatedKeyWithFlippedMSB checks that ciphertexts with its
// encapsulated key MSB flipped fails to decrypt. See details at b/213886185.
func TestDecryptEncapsulatedKeyWithFlippedMSB(t *testing.T) {
	pubKey, privKey := pubPrivKeys(t, validParams(t))
	enc, err := NewEncrypt(pubKey)
	if err != nil {
		t.Fatalf("NewEncrypt: err %q", err)
	}
	dec, err := NewDecrypt(privKey)
	if err != nil {
		t.Fatalf("NewDecrypt: err %q", err)
	}

	wantPT := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)
	ct, err := enc.Encrypt(wantPT, ctxInfo)
	if err != nil {
		t.Fatalf("Encrypt: err %q", err)
	}
	gotPT, err := dec.Decrypt(ct, ctxInfo)
	if err != nil {
		t.Fatalf("Decrypt: err %q", err)
	}
	if !bytes.Equal(gotPT, wantPT) {
		t.Errorf("Decrypt: got %q, want %q", gotPT, wantPT)
	}

	// Flip the MSB of the encapsulated key, which is the first 32 bytes of ct.
	ct[31] = ct[31] ^ 128
	if _, err := dec.Decrypt(ct, ctxInfo); err == nil {
		t.Error("Decrypt with encapsulated key MSB flipped: got success, want err")
	}
}

func validParams(t *testing.T) *pb.HpkeParams {
	t.Helper()
	return &pb.HpkeParams{
		Kem:  pb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		Kdf:  pb.HpkeKdf_HKDF_SHA256,
		Aead: pb.HpkeAead_AES_256_GCM,
	}
}

func pubPrivKeys(t *testing.T, params *pb.HpkeParams) (*pb.HpkePublicKey, *pb.HpkePrivateKey) {
	t.Helper()

	priv, err := subtle.GeneratePrivateKeyX25519()
	if err != nil {
		t.Fatalf("GeneratePrivateKeyX25519: err %q", err)
	}
	pub, err := subtle.PublicFromPrivateX25519(priv)
	if err != nil {
		t.Fatalf("PublicFromPrivateX25519: err %q", err)
	}

	pubKey := &pb.HpkePublicKey{
		Version:   0,
		Params:    params,
		PublicKey: pub,
	}
	privKey := &pb.HpkePrivateKey{
		Version:    0,
		PublicKey:  pubKey,
		PrivateKey: priv,
	}
	return pubKey, privKey
}

func flipRandByte(t *testing.T, b []byte) []byte {
	t.Helper()
	ret := make([]byte, len(b))
	copy(ret, b)
	randByte := rand.Intn(len(b))
	ret[randByte] = ret[randByte] ^ 255
	return ret
}
