// Copyright 2020 Google LLC
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

package subtle_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
)

func TestAESGCMSIVRejectsInvalidKeyLength(t *testing.T) {
	invalidKeySizes := []uint32{4, 8, 12, 15, 17, 24, 30, 31, 33, 64, 128}

	for _, keySize := range invalidKeySizes {
		key := random.GetRandomBytes(keySize)

		if _, err := subtle.NewAESGCMSIV(key); err == nil {
			t.Errorf("expected error with invalid key-size %d", keySize)
		}
	}
}

func TestAESGCMSIVRandomNonceProducesDifferentCiphertexts(t *testing.T) {
	nSample := 1 << 17
	key := random.GetRandomBytes(16)
	pt := []byte{}
	ad := []byte{}
	a, _ := subtle.NewAESGCMSIV(key)
	ctSet := make(map[string]bool)

	for i := 0; i < nSample; i++ {
		ct, _ := a.Encrypt(pt, ad)
		ctHex := hex.EncodeToString(ct)

		if _, existed := ctSet[ctHex]; existed {
			t.Errorf("nonce is repeated after %d samples", i)
		}
		ctSet[ctHex] = true
	}
}

func TestAESGCMSIVModifyCiphertext(t *testing.T) {
	ad := random.GetRandomBytes(33)
	key := random.GetRandomBytes(16)
	pt := random.GetRandomBytes(32)
	a, _ := subtle.NewAESGCMSIV(key)
	ct, _ := a.Encrypt(pt, ad)
	// flipping bits
	for i := 0; i < len(ct); i++ {
		tmp := ct[i]
		for j := 0; j < 8; j++ {
			ct[i] ^= 1 << uint8(j)
			if _, err := a.Decrypt(ct, ad); err == nil {
				t.Errorf("expect an error when flipping bit of ciphertext: byte %d, bit %d", i, j)
			}
			ct[i] = tmp
		}
	}
	// truncated ciphertext
	for i := 1; i < len(ct); i++ {
		if _, err := a.Decrypt(ct[:i], ad); err == nil {
			t.Errorf("expect an error ciphertext is truncated until byte %d", i)
		}
	}
	// modify additional authenticated data
	for i := 0; i < len(ad); i++ {
		tmp := ad[i]
		for j := 0; j < 8; j++ {
			ad[i] ^= 1 << uint8(j)
			if _, err := a.Decrypt(ct, ad); err == nil {
				t.Errorf("expect an error when flipping bit of ad: byte %d, bit %d", i, j)
			}
			ad[i] = tmp
		}
	}
}

func TestAESGCMSIVWycheproofCases(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	suite := new(AEADSuite)
	if err := testutil.PopulateSuite(suite, "aes_gcm_siv_test.json"); err != nil {
		t.Fatalf("failed populating suite: %s", err)
	}
	for _, group := range suite.TestGroups {
		for _, test := range group.Tests {
			caseName := fmt.Sprintf("%s-%s(%d):Case-%d", suite.Algorithm, group.Type, group.KeySize, test.CaseID)
			t.Run("DecryptOnly/"+caseName, func(t *testing.T) { runWycheproofDecryptOnly(t, test) })
			t.Run("EncryptDecrypt/"+caseName, func(t *testing.T) { runWycheproofEncryptDecrypt(t, test) })
		}
	}
}

func runWycheproofDecryptOnly(t *testing.T, testCase *AEADCase) {
	aead, err := subtle.NewAESGCMSIV(testCase.Key)
	if err != nil {
		t.Fatalf("cannot create aead, error: %v", err)
	}

	var combinedCt []byte
	combinedCt = append(combinedCt, testCase.Iv...)
	combinedCt = append(combinedCt, testCase.Ct...)
	combinedCt = append(combinedCt, testCase.Tag...)
	decrypted, err := aead.Decrypt(combinedCt, testCase.Aad)
	switch testCase.Result {
	case "valid":
		if err != nil {
			t.Errorf("unexpected error in test-case: %v", err)
		} else if !bytes.Equal(decrypted, testCase.Msg) {
			t.Errorf(
				"incorrect decryption: actual: %s; expected %s",
				hex.EncodeToString(decrypted), hex.EncodeToString(testCase.Msg))
		}
	case "invalid":
		if err == nil && bytes.Equal(testCase.Ct, decrypted) {
			t.Error("successfully decrypted invalid test-case")
		}
	default:
		t.Errorf("unknown test-case result: %s", testCase.Result)
	}
}

func runWycheproofEncryptDecrypt(t *testing.T, testCase *AEADCase) {
	aead, err := subtle.NewAESGCMSIV(testCase.Key)
	if err != nil {
		t.Fatalf("cannot create aead, error: %v", err)
	}

	ct, err := aead.Encrypt(testCase.Msg, testCase.Aad)
	if err != nil {
		if testCase.Result != "invalid" {
			t.Errorf("unexpected error in test-case: %v", err)
		}
		return
	}

	decrypted, err := aead.Decrypt(ct, testCase.Aad)
	switch testCase.Result {
	case "valid":
		if err != nil {
			t.Errorf("unexpected error in test-case: %v", err)
		} else if !bytes.Equal(decrypted, testCase.Msg) {
			t.Errorf(
				"incorrect decryption: actual: %s; expected %s",
				hex.EncodeToString(decrypted), hex.EncodeToString(testCase.Msg))
		}
	case "invalid":
		if err == nil && bytes.Equal(ct, decrypted) {
			t.Error("successfully decrypted invalid test-case")
		}
	default:
		t.Errorf("unknown test-case result: %s", testCase.Result)
	}
}
