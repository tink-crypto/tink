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

package internal

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/tink/go/testutil"
)

// TODO(b/201070904): Separate tests into internal_test package.

var hpkeAeadIds = []struct {
	name   string
	aeadID uint16
}{
	{"AES128GCM", aes128GCM},
	{"AES256GCM", aes256GCM},
	{"ChaCha20Poly1305", chaCha20Poly1305},
	{"ExportOnlyAEAD", 0xFFFF},
}

type hpkeID struct {
	mode   uint8
	kemID  uint16
	kdfID  uint16
	aeadID uint16
}

type hpkeVector struct {
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

type hpkeEncryptionVector struct {
	key            []byte
	plaintext      []byte
	associatedData []byte
	nonce          []byte
	ciphertext     []byte
}

// TODO(b/201070904): Include all Tink-supported I-D test vectors.
func hpkeInternetDraftTestVector(t *testing.T) (hpkeID, hpkeVector, error) {
	t.Helper()

	// Test vector from HPKE I-D
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#appendix-A.1.1.
	v := struct {
		mode                                                                                    uint8
		kemID, kdfID, aeadID                                                                    uint16
		info, pkEm, skEm, pkRm, skRm, enc, sharedSecret, keyScheduleCtx, secret, key, baseNonce string
	}{
		mode:           0,
		kemID:          32,
		kdfID:          1,
		aeadID:         1,
		info:           "4f6465206f6e2061204772656369616e2055726e",
		pkEm:           "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
		skEm:           "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
		pkRm:           "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
		skRm:           "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
		enc:            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
		sharedSecret:   "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
		keyScheduleCtx: "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449",
		secret:         "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397",
		key:            "4531685d41d65f03dc48f6b8302c05b0",
		baseNonce:      "56d890e5accaaf011cff4b7d",
	}

	var info, senderPubKey, senderPrivKey, recipientPubKey, recipientPrivKey, encapsulatedKey, sharedSecret, keyScheduleCtx, secret, key, baseNonce []byte
	var err error
	if info, err = hex.DecodeString(v.info); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(info) failed")
	}
	if senderPubKey, err = hex.DecodeString(v.pkEm); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(pkEm) failed")
	}
	if senderPrivKey, err = hex.DecodeString(v.skEm); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(skEm) failed")
	}
	if recipientPubKey, err = hex.DecodeString(v.pkRm); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(pkRm) failed")
	}
	if recipientPrivKey, err = hex.DecodeString(v.skRm); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(skRm) failed")
	}
	if encapsulatedKey, err = hex.DecodeString(v.enc); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(enc) failed")
	}
	if sharedSecret, err = hex.DecodeString(v.sharedSecret); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(sharedSecret) failed")
	}
	if keyScheduleCtx, err = hex.DecodeString(v.keyScheduleCtx); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(keyScheduleCtx) failed")
	}
	if secret, err = hex.DecodeString(v.secret); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(secret) failed")
	}
	if key, err = hex.DecodeString(v.key); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(key) failed")
	}
	if baseNonce, err = hex.DecodeString(v.baseNonce); err != nil {
		return hpkeID{}, hpkeVector{}, errors.New("hex.DecodeString(baseNonce) failed")
	}

	return hpkeID{
			mode:   v.mode,
			kemID:  v.kemID,
			kdfID:  v.kdfID,
			aeadID: v.aeadID,
		},
		hpkeVector{
			info:             info,
			senderPubKey:     senderPubKey,
			senderPrivKey:    senderPrivKey,
			recipientPubKey:  recipientPubKey,
			recipientPrivKey: recipientPrivKey,
			encapsulatedKey:  encapsulatedKey,
			sharedSecret:     sharedSecret,
			keyScheduleCtx:   keyScheduleCtx,
			secret:           secret,
			key:              key,
			baseNonce:        baseNonce,
		}, nil
}

func hpkeAESGCMEncryptionVectors(t *testing.T) map[hpkeID]hpkeEncryptionVector {
	t.Helper()

	// Test vectors from HPKE I-D. Must only include AES-GCM vectors.
	vecs := []struct {
		mode                                              uint8
		kemID, kdfID, aeadID                              uint16
		key, plaintext, associatedData, nonce, ciphertext string
	}{
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#appendix-A.1.1.1
		{
			mode:           0,
			kemID:          32,
			kdfID:          1,
			aeadID:         1,
			key:            "4531685d41d65f03dc48f6b8302c05b0",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d30",
			nonce:          "56d890e5accaaf011cff4b7d",
			ciphertext:     "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
		},
		{
			mode:           0,
			kemID:          32,
			kdfID:          1,
			aeadID:         1,
			key:            "4531685d41d65f03dc48f6b8302c05b0",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d31",
			nonce:          "56d890e5accaaf011cff4b7c",
			ciphertext:     "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
		},
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#appendix-A.6.1.1
		{
			mode:           0,
			kemID:          18,
			kdfID:          3,
			aeadID:         2,
			key:            "751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d30",
			nonce:          "55ff7a7d739c69f44b25447b",
			ciphertext:     "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a",
		},
		{
			mode:           0,
			kemID:          18,
			kdfID:          3,
			aeadID:         2,
			key:            "751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d31",
			nonce:          "55ff7a7d739c69f44b25447a",
			ciphertext:     "d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256",
		},
	}

	m := make(map[hpkeID]hpkeEncryptionVector)
	for _, v := range vecs {
		var key, plaintext, associatedData, nonce, ciphertext []byte
		var err error
		if key, err = hex.DecodeString(v.key); err != nil {
			t.Fatalf("hex.DecodeString(key): err %q", err)
		}
		if plaintext, err = hex.DecodeString(v.plaintext); err != nil {
			t.Fatalf("hex.DecodeString(plaintext): err %q", err)
		}
		if associatedData, err = hex.DecodeString(v.associatedData); err != nil {
			t.Fatalf("hex.DecodeString(associatedData): err %q", err)
		}
		if nonce, err = hex.DecodeString(v.nonce); err != nil {
			t.Fatalf("hex.DecodeString(nonce): err %q", err)
		}
		if ciphertext, err = hex.DecodeString(v.ciphertext); err != nil {
			t.Fatalf("hex.DecodeString(ciphertext): err %q", err)
		}

		id := hpkeID{v.mode, v.kemID, v.kdfID, v.aeadID}
		m[id] = hpkeEncryptionVector{
			key:            key,
			plaintext:      plaintext,
			associatedData: associatedData,
			nonce:          nonce,
			ciphertext:     ciphertext,
		}
	}

	return m
}

func hpkeX25519HkdfSha256BaseModeTestVectors(t *testing.T) map[hpkeID]hpkeVector {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	t.Helper()

	srcDir, _ := os.LookupEnv("TEST_SRCDIR")
	path := filepath.Join(srcDir, os.Getenv("TEST_WORKSPACE"), "/hybrid/internal/testdata/boringssl_hpke_test_vectors.json")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	var vecs []struct {
		Mode             uint8             `json:"mode"`
		KEMID            uint16            `json:"kem_id"`
		KDFID            uint16            `json:"kdf_id"`
		AEADID           uint16            `json:"aead_id"`
		Info             testutil.HexBytes `json:"info"`
		SenderPubKey     testutil.HexBytes `json:"pkEm"`
		SenderPrivKey    testutil.HexBytes `json:"skEm"`
		RecipientPubKey  testutil.HexBytes `json:"pkRm"`
		RecipientPrivKey testutil.HexBytes `json:"skRm"`
		EncapsulatedKey  testutil.HexBytes `json:"enc"`
		SharedSecret     testutil.HexBytes `json:"shared_secret"`
		KeyScheduleCtx   testutil.HexBytes `json:"key_schedule_context"`
		Secret           testutil.HexBytes `json:"secret"`
		Key              testutil.HexBytes `json:"key"`
		BaseNonce        testutil.HexBytes `json:"base_nonce"`
	}
	parser := json.NewDecoder(f)
	if err := parser.Decode(&vecs); err != nil {
		t.Fatal(err)
	}

	m := make(map[hpkeID]hpkeVector)
	for _, v := range vecs {
		if v.Mode != baseMode || v.KEMID != x25519HkdfSha256 {
			continue
		}

		id := hpkeID{v.Mode, v.KEMID, v.KDFID, v.AEADID}
		m[id] = hpkeVector{
			info:             v.Info,
			senderPubKey:     v.SenderPubKey,
			senderPrivKey:    v.SenderPrivKey,
			recipientPubKey:  v.RecipientPubKey,
			recipientPrivKey: v.RecipientPrivKey,
			encapsulatedKey:  v.EncapsulatedKey,
			sharedSecret:     v.SharedSecret,
			keyScheduleCtx:   v.KeyScheduleCtx,
			secret:           v.Secret,
			key:              v.Key,
			baseNonce:        v.BaseNonce,
		}
	}

	return m
}
