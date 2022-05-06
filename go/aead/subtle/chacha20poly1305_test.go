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
	"math/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
)

func TestChaCha20Poly1305EncryptDecrypt(t *testing.T) {
	for i, test := range chaCha20Poly1305Tests {
		key, _ := hex.DecodeString(test.key)
		pt, _ := hex.DecodeString(test.plaintext)
		ad, _ := hex.DecodeString(test.associatedData)
		nonce, _ := hex.DecodeString(test.nonce)
		out, _ := hex.DecodeString(test.out)

		ca, err := subtle.NewChaCha20Poly1305(key)
		if err != nil {
			t.Errorf("#%d, cannot create new instance of ChaCha20Poly1305: %s", i, err)
			continue
		}

		_, err = ca.Encrypt(pt, ad)
		if err != nil {
			t.Errorf("#%d, unexpected encryption error: %s", i, err)
			continue
		}

		var combinedCT []byte
		combinedCT = append(combinedCT, nonce...)
		combinedCT = append(combinedCT, out...)
		if got, err := ca.Decrypt(combinedCT, ad); err != nil {
			t.Errorf("#%d, unexpected decryption error: %s", i, err)
			continue
		} else if !bytes.Equal(pt, got) {
			t.Errorf("#%d, plaintext's don't match: got %x vs %x", i, got, pt)
			continue
		}
	}
}

func TestChaCha20Poly1305EmptyAssociatedData(t *testing.T) {
	key := random.GetRandomBytes(chacha20poly1305.KeySize)
	emptyAD := []byte{}
	badAD := []byte{1, 2, 3}

	ca, err := subtle.NewChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 75; i++ {
		pt := random.GetRandomBytes(uint32(i))
		// Encrypting with associatedData as a 0-length array
		{
			ct, err := ca.Encrypt(pt, emptyAD)
			if err != nil {
				t.Errorf("Encrypt(%x, %x) failed", pt, emptyAD)
				continue
			}

			if got, err := ca.Decrypt(ct, emptyAD); err != nil || !bytes.Equal(pt, got) {
				t.Errorf("Decrypt(Encrypt(pt, %x)): plaintext's don't match: got %x vs %x", emptyAD, got, pt)
			}
			if got, err := ca.Decrypt(ct, nil); err != nil || !bytes.Equal(pt, got) {
				t.Errorf("Decrypt(Encrypt(pt, nil)): plaintext's don't match: got %x vs %x", got, pt)
			}
			if _, err := ca.Decrypt(ct, badAD); err == nil {
				t.Errorf("Decrypt(Encrypt(pt, %x)) = _, nil; want: _, err", badAD)
			}
		}
		// Encrypting with associatedData equal to nil
		{
			ct, err := ca.Encrypt(pt, nil)
			if err != nil {
				t.Errorf("Encrypt(%x, nil) failed", pt)
			}

			if got, err := ca.Decrypt(ct, emptyAD); err != nil || !bytes.Equal(pt, got) {
				t.Errorf("Decrypt(Encrypt(pt, %x)): plaintext's don't match: got %x vs %x; error: %v", emptyAD, got, pt, err)
			}
			if got, err := ca.Decrypt(ct, nil); err != nil || !bytes.Equal(pt, got) {
				t.Errorf("Decrypt(Encrypt(pt, nil)): plaintext's don't match: got %x vs %x; error: %v", got, pt, err)
			}
			if _, err := ca.Decrypt(ct, badAD); err == nil {
				t.Errorf("Decrypt(Encrypt(pt, %x)) = _, nil; want: _, err", badAD)
			}
		}
	}
}

func TestChaCha20Poly1305LongMessages(t *testing.T) {
	dataSize := uint32(16)
	// Encrypts and decrypts messages of size <= 8192.
	for dataSize <= 1<<24 {
		pt := random.GetRandomBytes(dataSize)
		ad := random.GetRandomBytes(dataSize / 3)
		key := random.GetRandomBytes(chacha20poly1305.KeySize)

		ca, err := subtle.NewChaCha20Poly1305(key)
		if err != nil {
			t.Fatal(err)
		}

		ct, err := ca.Encrypt(pt, ad)
		if err != nil {
			t.Errorf("Encrypt(%x, %x) failed", pt, ad)
			continue
		}

		if got, err := ca.Decrypt(ct, ad); err != nil || !bytes.Equal(pt, got) {
			t.Errorf("Decrypt(Encrypt(pt, %x)): plaintext's don't match: got %x vs %x; error: %v", ad, got, pt, err)
		}

		dataSize += 5 * dataSize / 11
	}
}

func TestChaCha20Poly1305ModifyCiphertext(t *testing.T) {
	for i, test := range chaCha20Poly1305Tests {
		key, _ := hex.DecodeString(test.key)
		pt, _ := hex.DecodeString(test.plaintext)
		ad, _ := hex.DecodeString(test.associatedData)

		ca, err := subtle.NewChaCha20Poly1305(key)
		if err != nil {
			t.Fatal(err)
		}

		ct, err := ca.Encrypt(pt, ad)
		if err != nil {
			t.Errorf("#%d: Encrypt failed", i)
			continue
		}

		if len(ad) > 0 {
			alteredIndex := rand.Intn(len(ad))
			ad[alteredIndex] ^= 0x80
			if _, err := ca.Decrypt(ct, ad); err == nil {
				t.Errorf("#%d: Decrypt was successful after altering additional data", i)
				continue
			}
			ad[alteredIndex] ^= 0x80
		}

		alterCtIdx := rand.Intn(len(ct))
		ct[alterCtIdx] ^= 0x80
		if _, err := ca.Decrypt(ct, ad); err == nil {
			t.Errorf("#%d: Decrypt was successful after altering ciphertext", i)
			continue
		}
		ct[alterCtIdx] ^= 0x80
	}
}

// This is a very simple test for the randomness of the nonce.
// The test simply checks that the multiple ciphertexts of the same message are distinct.
func TestChaCha20Poly1305RandomNonce(t *testing.T) {
	key := random.GetRandomBytes(chacha20poly1305.KeySize)
	ca, err := subtle.NewChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}

	cts := make(map[string]bool)
	pt, ad := []byte{}, []byte{}
	for i := 0; i < 1<<10; i++ {
		ct, err := ca.Encrypt(pt, ad)
		ctHex := hex.EncodeToString(ct)
		if err != nil || cts[ctHex] {
			t.Errorf("TestRandomNonce failed: %v", err)
		} else {
			cts[ctHex] = true
		}
	}
}

func TestChaCha20Poly1305WycheproofCases(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	suite := new(AEADSuite)
	if err := testutil.PopulateSuite(suite, "chacha20_poly1305_test.json"); err != nil {
		t.Fatalf("failed populating suite: %s", err)
	}
	for _, group := range suite.TestGroups {
		if group.KeySize/8 != chacha20poly1305.KeySize {
			continue
		}
		if group.IvSize/8 != chacha20poly1305.NonceSize {
			continue
		}

		for _, test := range group.Tests {
			caseName := fmt.Sprintf("%s-%s:Case-%d", suite.Algorithm, group.Type, test.CaseID)
			t.Run(caseName, func(t *testing.T) { runChaCha20Poly1305WycheproofCase(t, test) })
		}
	}
}

func runChaCha20Poly1305WycheproofCase(t *testing.T, tc *AEADCase) {
	var combinedCT []byte
	combinedCT = append(combinedCT, tc.Iv...)
	combinedCT = append(combinedCT, tc.Ct...)
	combinedCT = append(combinedCT, tc.Tag...)

	ca, err := subtle.NewChaCha20Poly1305(tc.Key)
	if err != nil {
		t.Fatalf("cannot create new instance of ChaCha20Poly1305: %s", err)
	}

	_, err = ca.Encrypt(tc.Msg, tc.Aad)
	if err != nil {
		t.Fatalf("unexpected encryption error: %s", err)
	}

	decrypted, err := ca.Decrypt(combinedCT, tc.Aad)
	if err != nil {
		if tc.Result == "valid" {
			t.Errorf("unexpected error: %s", err)
		}
	} else {
		if tc.Result == "invalid" {
			t.Error("decrypted invalid")
		}
		if !bytes.Equal(decrypted, tc.Msg) {
			t.Error("incorrect decryption")
		}
	}
}
