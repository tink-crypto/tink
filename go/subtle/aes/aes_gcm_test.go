// Copyright 2017 Google Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
////////////////////////////////////////////////////////////////////////////////

package aes_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/google/tink/go/subtle/aes"
	"github.com/google/tink/go/subtle/random"
	"os"
	"testing"
)

var keySizes = []int{16, 24, 32}

// Since the tag size depends on the Seal() function of crypto library,
// this test checks that the tag size is always 128 bit.
func TestAesGcmTagLength(t *testing.T) {
	for _, keySize := range keySizes {
		key := random.GetRandomBytes(uint32(keySize))
		a, _ := aes.NewAesGcm(key)
		ad := random.GetRandomBytes(32)
		pt := random.GetRandomBytes(32)
		ct, _ := a.Encrypt(pt, ad)
		actualTagSize := len(ct) - aes.AES_GCM_IV_SIZE - len(pt)
		if actualTagSize != aes.AES_GCM_TAG_SIZE {
			t.Errorf("tag size is not 128 bit, it is %d bit", actualTagSize*8)
		}
	}
}

func TestAesGcmKeySize(t *testing.T) {
	for _, keySize := range keySizes {
		if _, err := aes.NewAesGcm(make([]byte, keySize)); err != nil {
			t.Errorf("unexpected error when key size is %d btyes", keySize)
		}
		if _, err := aes.NewAesGcm(make([]byte, keySize+1)); err == nil {
			t.Errorf("expect an error when key size is not supported %d", keySize)
		}
	}
}

func TestAesGcmEncryptDecrypt(t *testing.T) {
	for _, keySize := range keySizes {
		key := random.GetRandomBytes(uint32(keySize))
		a, err := aes.NewAesGcm(key)
		if err != nil {
			t.Errorf("unexpected error when creating new cipher: %s", err)
		}
		ad := random.GetRandomBytes(5)
		for ptSize := 0; ptSize < 75; ptSize++ {
			pt := random.GetRandomBytes(uint32(ptSize))
			ct, err := a.Encrypt(pt, ad)
			if err != nil {
				t.Errorf("unexpected error in encryption: keySize %v, ptSize %v", keySize, ptSize)
			}
			decrypted, err := a.Decrypt(ct, ad)
			if err != nil {
				t.Errorf("unexpected error in decryption: keySize %v, ptSize %v", keySize, ptSize)
			}
			if !bytes.Equal(pt, decrypted) {
				t.Errorf("decrypted text and plaintext don't match: keySize %v, ptSize %v", keySize, ptSize)
			}
		}
	}
}

func TestAesGcmLongMessages(t *testing.T) {
	ptSize := 16
	for ptSize <= 1<<24 {
		pt := random.GetRandomBytes(uint32(ptSize))
		ad := random.GetRandomBytes(uint32(ptSize / 3))
		for _, keySize := range keySizes {
			key := random.GetRandomBytes(uint32(keySize))
			a, _ := aes.NewAesGcm(key)
			ct, _ := a.Encrypt(pt, ad)
			decrypted, _ := a.Decrypt(ct, ad)
			if !bytes.Equal(pt, decrypted) {
				t.Errorf("decrypted text and plaintext don't match: keySize %v, ptSize %v", keySize, ptSize)
			}
		}
		ptSize += 5 * ptSize / 11
	}
}

func TestAesGcmModifyCiphertext(t *testing.T) {
	ad := random.GetRandomBytes(33)
	key := random.GetRandomBytes(16)
	pt := random.GetRandomBytes(32)
	a, _ := aes.NewAesGcm(key)
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
			t.Errorf("expect an error ciphertext is truncated until byte %s", i)
		}
	}
	// modify additinal authenticated data
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

/**
 * This is a very simple test for the randomness of the nonce.
 * The test simply checks that the multiple ciphertexts of the same
 * message are distinct.
 */
func TestAesGcmRandomNonce(t *testing.T) {
	nSample := 1 << 17
	key := random.GetRandomBytes(16)
	pt := []byte{}
	ad := []byte{}
	a, _ := aes.NewAesGcm(key)
	ctSet := make(map[string]bool)
	for i := 0; i < nSample; i++ {
		ct, _ := a.Encrypt(pt, ad)
		ctHex := hex.EncodeToString(ct)
		_, existed := ctSet[ctHex]
		if existed {
			t.Errorf("nonce is repeated after %d samples", i)
		}
		ctSet[ctHex] = true
	}
}

type testdata struct {
	Algorithm        string
	GeneratorVersion string
	NumberOfTests    uint32
	TestGroups       []*testgroup
}

type testgroup struct {
	IvSize  uint32
	KeySize uint32
	TagSize uint32
	Type    string
	Tests   []*testcase
}

type testcase struct {
	Aad     string
	Comment string
	Ct      string
	Iv      string
	Key     string
	Msg     string
	Result  string
	Tag     string
	TcId    uint32
}

func TestVectors(t *testing.T) {
	f, err := os.Open("../../../wycheproof/testvectors/aes_gcm_test.json")
	if err != nil {
		t.Fatal("cannot open file: %s", err)
	}
	parser := json.NewDecoder(f)
	data := new(testdata)
	if err := parser.Decode(data); err != nil {
		t.Fatal("cannot decode test data: %s", err)
	}

	for _, g := range data.TestGroups {
		if err := aes.ValidateAesKeySize(g.KeySize / 8); err != nil {
			continue
		}
		if g.IvSize != aes.AES_GCM_IV_SIZE*8 {
			continue
		}
		for _, tc := range g.Tests {
			key, err := hex.DecodeString(tc.Key)
			if err != nil {
				t.Errorf("cannot decode key in test case %d: %s", tc.TcId, err)
			}
			aad, err := hex.DecodeString(tc.Aad)
			if err != nil {
				t.Errorf("cannot decode aad in test case %d: %s", tc.TcId, err)
			}
			msg, err := hex.DecodeString(tc.Msg)
			if err != nil {
				t.Errorf("cannot decode msg in test case %d: %s", tc.TcId, err)
			}
			ct, err := hex.DecodeString(tc.Ct)
			if err != nil {
				t.Errorf("cannot decode ct in test case %d: %s", tc.TcId, err)
			}
			iv, err := hex.DecodeString(tc.Iv)
			if err != nil {
				t.Errorf("cannot decode iv in test case %d: %s", tc.TcId, err)
			}
			tag, err := hex.DecodeString(tc.Tag)
			if err != nil {
				t.Errorf("cannot decode tag in test case %d: %s", tc.TcId, err)
			}
			var combinedCt []byte
			combinedCt = append(combinedCt, iv...)
			combinedCt = append(combinedCt, ct...)
			combinedCt = append(combinedCt, tag...)
			// create cipher and do encryption
			cipher, err := aes.NewAesGcm(key)
			if err != nil {
				t.Errorf("cannot create new instance of AesGcm in test case %d: %s", tc.TcId, err)
				continue
			}
			decrypted, err := cipher.Decrypt(combinedCt, aad)
			if err != nil {
				t.Errorf("unexpected error in test case %d: %s", tc.TcId, err)
			}
			if bytes.Compare(decrypted, msg) != 0 {
				t.Errorf("failed in test case %d", tc.TcId)
			}
		}
	}
}
