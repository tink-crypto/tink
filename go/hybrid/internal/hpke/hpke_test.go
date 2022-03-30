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
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/tink/go/testutil"
)

// TODO(b/201070904): Separate tests into internal_test package.

// aeadIDs are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3.
var aeadIDs = []struct {
	name      string
	aeadID    uint16
	keyLength int
}{
	{"AES128GCM", aes128GCM, 16},
	{"AES256GCM", aes256GCM, 32},
	{"ChaCha20Poly1305", chaCha20Poly1305, 32},
}

type hpkeID struct {
	id     int
	mode   uint8
	kemID  uint16
	kdfID  uint16
	aeadID uint16
}

type vector struct {
	info                   []byte
	senderPubKey           []byte
	senderPrivKey          []byte
	recipientPubKey        []byte
	recipientPrivKey       []byte
	encapsulatedKey        []byte
	sharedSecret           []byte
	keyScheduleCtx         []byte
	secret                 []byte
	key                    []byte
	baseNonce              []byte
	consecutiveEncryptions []encryptionVector
	otherEncryptions       []encryptionVector
}

type encryptionVector struct {
	key            []byte
	plaintext      []byte
	associatedData []byte
	nonce          []byte
	ciphertext     []byte
	sequenceNumber *big.Int
}

type encryptionString struct {
	sequenceNumber uint64
	plaintext      string
	associatedData string
	nonce          string
	ciphertext     string
}

// TODO(b/201070904): Include all Tink-supported RFC vectors.
func internetDraftVector(t *testing.T) (hpkeID, vector) {
	t.Helper()

	// Test vector from HPKE RFC
	// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1.
	v := struct {
		mode                                                                                    uint8
		kemID, kdfID, aeadID                                                                    uint16
		info, pkEm, skEm, pkRm, skRm, enc, sharedSecret, keyScheduleCtx, secret, key, baseNonce string
		consecutiveEncryptions, otherEncryptions                                                []encryptionString
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
		consecutiveEncryptions: []encryptionString{
			{
				sequenceNumber: 0,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d30",
				nonce:          "56d890e5accaaf011cff4b7d",
				ciphertext:     "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
			},
			{
				sequenceNumber: 1,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d31",
				nonce:          "56d890e5accaaf011cff4b7c",
				ciphertext:     "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
			},
			{
				sequenceNumber: 2,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d32",
				nonce:          "56d890e5accaaf011cff4b7f",
				ciphertext:     "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
			},
		},
		otherEncryptions: []encryptionString{
			{
				sequenceNumber: 4,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d34",
				nonce:          "56d890e5accaaf011cff4b79",
				ciphertext:     "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d",
			},
			{
				sequenceNumber: 255,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d323535",
				nonce:          "56d890e5accaaf011cff4b82",
				ciphertext:     "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a",
			},
			{
				sequenceNumber: 256,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d323536",
				nonce:          "56d890e5accaaf011cff4a7d",
				ciphertext:     "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2",
			},
		},
	}

	var info, senderPubKey, senderPrivKey, recipientPubKey, recipientPrivKey, encapsulatedKey, sharedSecret, keyScheduleCtx, secret, key, baseNonce []byte
	var err error
	if info, err = hex.DecodeString(v.info); err != nil {
		t.Fatalf("hex.DecodeString(info): err %q", err)
	}
	if senderPubKey, err = hex.DecodeString(v.pkEm); err != nil {
		t.Fatalf("hex.DecodeString(pkEm): err %q", err)
	}
	if senderPrivKey, err = hex.DecodeString(v.skEm); err != nil {
		t.Fatalf("hex.DecodeString(skEm): err %q", err)
	}
	if recipientPubKey, err = hex.DecodeString(v.pkRm); err != nil {
		t.Fatalf("hex.DecodeString(pkRm): err %q", err)
	}
	if recipientPrivKey, err = hex.DecodeString(v.skRm); err != nil {
		t.Fatalf("hex.DecodeString(skRm): err %q", err)
	}
	if encapsulatedKey, err = hex.DecodeString(v.enc); err != nil {
		t.Fatalf("hex.DecodeString(enc): err %q", err)
	}
	if sharedSecret, err = hex.DecodeString(v.sharedSecret); err != nil {
		t.Fatalf("hex.DecodeString(sharedSecret): err %q", err)
	}
	if keyScheduleCtx, err = hex.DecodeString(v.keyScheduleCtx); err != nil {
		t.Fatalf("hex.DecodeString(keyScheduleCtx): err %q", err)
	}
	if secret, err = hex.DecodeString(v.secret); err != nil {
		t.Fatalf("hex.DecodeString(secret): err %q", err)
	}
	if key, err = hex.DecodeString(v.key); err != nil {
		t.Fatalf("hex.DecodeString(key): err %q", err)
	}
	if baseNonce, err = hex.DecodeString(v.baseNonce); err != nil {
		t.Fatalf("hex.DecodeString(baseNonce): err %q", err)
	}

	return hpkeID{0 /*=id */, v.mode, v.kemID, v.kdfID, v.aeadID},
		vector{
			info:                   info,
			senderPubKey:           senderPubKey,
			senderPrivKey:          senderPrivKey,
			recipientPubKey:        recipientPubKey,
			recipientPrivKey:       recipientPrivKey,
			encapsulatedKey:        encapsulatedKey,
			sharedSecret:           sharedSecret,
			keyScheduleCtx:         keyScheduleCtx,
			secret:                 secret,
			key:                    key,
			baseNonce:              baseNonce,
			consecutiveEncryptions: parseEncryptions(t, v.consecutiveEncryptions),
			otherEncryptions:       parseEncryptions(t, v.otherEncryptions),
		}
}

func parseEncryptions(t *testing.T, encs []encryptionString) []encryptionVector {
	t.Helper()

	var res []encryptionVector
	for _, e := range encs {
		var plaintext, associatedData, nonce, ciphertext []byte
		var err error
		if plaintext, err = hex.DecodeString(e.plaintext); err != nil {
			t.Fatalf("hex.DecodeString(plaintext): err %q", err)
		}
		if associatedData, err = hex.DecodeString(e.associatedData); err != nil {
			t.Fatalf("hex.DecodeString(associatedData): err %q", err)
		}
		if nonce, err = hex.DecodeString(e.nonce); err != nil {
			t.Fatalf("hex.DecodeString(nonce): err %q", err)
		}
		if ciphertext, err = hex.DecodeString(e.ciphertext); err != nil {
			t.Fatalf("hex.DecodeString(ciphertext): err %q", err)
		}

		res = append(res, encryptionVector{
			plaintext:      plaintext,
			associatedData: associatedData,
			nonce:          nonce,
			ciphertext:     ciphertext,
			sequenceNumber: big.NewInt(int64(e.sequenceNumber)),
		})
	}

	return res
}

// aeadRFCVectors returns RFC test vectors for AEAD IDs aes128GCM, aes256GCM,
// and chaCha20Poly1305.
func aeadRFCVectors(t *testing.T) map[hpkeID]encryptionVector {
	t.Helper()

	vecs := []struct {
		mode                                              uint8
		kemID, kdfID, aeadID                              uint16
		key, plaintext, associatedData, nonce, ciphertext string
	}{
		// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1.1
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
		// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.6.1.1
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
		// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.2.1.1
		{
			mode:           0,
			kemID:          32,
			kdfID:          1,
			aeadID:         3,
			key:            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d30",
			nonce:          "5c4d98150661b848853b547f",
			ciphertext:     "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
		},
		{
			mode:           0,
			kemID:          32,
			kdfID:          1,
			aeadID:         3,
			key:            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d31",
			nonce:          "5c4d98150661b848853b547e",
			ciphertext:     "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c",
		},
	}

	m := make(map[hpkeID]encryptionVector)
	for i, v := range vecs {
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

		id := hpkeID{i, v.mode, v.kemID, v.kdfID, v.aeadID}
		m[id] = encryptionVector{
			key:            key,
			plaintext:      plaintext,
			associatedData: associatedData,
			nonce:          nonce,
			ciphertext:     ciphertext,
		}
	}

	return m
}

// baseModeX25519HKDFSHA256Vectors returns BoringSSL test vectors for HPKE base
// mode with Diffie-Hellman-based X25519, HKDF-SHA256 KEM as per
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
func baseModeX25519HKDFSHA256Vectors(t *testing.T) map[hpkeID]vector {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	t.Helper()

	srcDir, _ := os.LookupEnv("TEST_SRCDIR")
	path := filepath.Join(srcDir, os.Getenv("TEST_WORKSPACE"), "/hybrid/internal/hpke/testdata/boringssl_hpke_test_vectors.json")
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

	m := make(map[hpkeID]vector)
	for i, v := range vecs {
		if v.Mode != baseMode || v.KEMID != x25519HKDFSHA256 {
			continue
		}

		id := hpkeID{i, v.Mode, v.KEMID, v.KDFID, v.AEADID}
		m[id] = vector{
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
