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

package aead_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"github.com/google/tink/go/subtle/aead"
	"github.com/google/tink/go/subtle/random"
)

func TestChaCha20Poly1305EncryptDecrypt(t *testing.T) {
	for i, test := range chaCha20Poly1305Tests {
		key, _ := hex.DecodeString(test.key)
		pt, _ := hex.DecodeString(test.plaintext)
		aad, _ := hex.DecodeString(test.aad)
		nonce, _ := hex.DecodeString(test.nonce)
		out, _ := hex.DecodeString(test.out)

		ca, err := aead.NewChaCha20Poly1305(key)
		if err != nil {
			t.Errorf("#%d, cannot create new instance of ChaCha20Poly1305: %s", i, err)
			continue
		}

		_, err = ca.Encrypt(pt, aad)
		if err != nil {
			t.Errorf("#%d, unexpected encryption error: %s", i, err)
			continue
		}

		var combinedCt []byte
		combinedCt = append(combinedCt, nonce...)
		combinedCt = append(combinedCt, out...)
		if got, err := ca.Decrypt(combinedCt, aad); err != nil {
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
	aad := []byte{}
	badAad := []byte{1, 2, 3}

	ca, err := aead.NewChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 75; i++ {
		pt := random.GetRandomBytes(uint32(i))
		// Encrpting with aad as a 0-length array
		{
			ct, err := ca.Encrypt(pt, aad)
			if err != nil {
				t.Errorf("Encrypt(%x, %x) failed", pt, aad)
				continue
			}

			if got, err := ca.Decrypt(ct, aad); err != nil || !bytes.Equal(pt, got) {
				t.Errorf("Decrypt(Encrypt(pt, %x)): plaintext's don't match: got %x vs %x", aad, got, pt)
			}
			if got, err := ca.Decrypt(ct, nil); err != nil || !bytes.Equal(pt, got) {
				t.Errorf("Decrypt(Encrypt(pt, nil)): plaintext's don't match: got %x vs %x", got, pt)
			}
			if _, err := ca.Decrypt(ct, badAad); err == nil {
				t.Errorf("Decrypt(Encrypt(pt, %x)) = _, nil; want: _, err", badAad)
			}
		}
		// Encrpting with aad equal to null
		{
			ct, err := ca.Encrypt(pt, nil)
			if err != nil {
				t.Errorf("Encrypt(%x, nil) failed", pt)
			}

			if got, err := ca.Decrypt(ct, aad); err != nil || !bytes.Equal(pt, got) {
				t.Errorf("Decrypt(Encrypt(pt, %x)): plaintext's don't match: got %x vs %x; error: %v", aad, got, pt, err)
			}
			if got, err := ca.Decrypt(ct, nil); err != nil || !bytes.Equal(pt, got) {
				t.Errorf("Decrypt(Encrypt(pt, nil)): plaintext's don't match: got %x vs %x; error: %v", got, pt, err)
			}
			if _, err := ca.Decrypt(ct, badAad); err == nil {
				t.Errorf("Decrypt(Encrypt(pt, %x)) = _, nil; want: _, err", badAad)
			}
		}
	}
}

func TestChaCha20Poly1305LongMessages(t *testing.T) {
	dataSize := uint32(16)
	// Encrypts and decrypts messages of size <= 8192.
	for dataSize <= 1<<24 {
		pt := random.GetRandomBytes(dataSize)
		aad := random.GetRandomBytes(dataSize / 3)
		key := random.GetRandomBytes(chacha20poly1305.KeySize)

		ca, err := aead.NewChaCha20Poly1305(key)
		if err != nil {
			t.Fatal(err)
		}

		ct, err := ca.Encrypt(pt, aad)
		if err != nil {
			t.Errorf("Encrypt(%x, %x) failed", pt, aad)
			continue
		}

		if got, err := ca.Decrypt(ct, aad); err != nil || !bytes.Equal(pt, got) {
			t.Errorf("Decrypt(Encrypt(pt, %x)): plaintext's don't match: got %x vs %x; error: %v", aad, got, pt, err)
		}

		dataSize += 5 * dataSize / 11
	}
}

func TestChaCha20Poly1305ModifyCiphertext(t *testing.T) {
	for i, test := range chaCha20Poly1305Tests {
		key, _ := hex.DecodeString(test.key)
		pt, _ := hex.DecodeString(test.plaintext)
		aad, _ := hex.DecodeString(test.aad)

		ca, err := aead.NewChaCha20Poly1305(key)
		if err != nil {
			t.Fatal(err)
		}

		ct, err := ca.Encrypt(pt, aad)
		if err != nil {
			t.Errorf("#%d: Encrypt failed", i)
			continue
		}

		if len(aad) > 0 {
			alterAadIdx := rand.Intn(len(aad))
			aad[alterAadIdx] ^= 0x80
			if _, err := ca.Decrypt(ct, aad); err == nil {
				t.Errorf("#%d: Decrypt was successful after altering additional data", i)
				continue
			}
			aad[alterAadIdx] ^= 0x80
		}

		alterCtIdx := rand.Intn(len(ct))
		ct[alterCtIdx] ^= 0x80
		if _, err := ca.Decrypt(ct, aad); err == nil {
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
	ca, err := aead.NewChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}

	cts := make(map[string]bool)
	pt, aad := []byte{}, []byte{}
	for i := 0; i < 1<<10; i++ {
		ct, err := ca.Encrypt(pt, aad)
		ctHex := hex.EncodeToString(ct)
		if err != nil || cts[ctHex] {
			t.Errorf("TestRandomNonce failed: %v", err)
		} else {
			cts[ctHex] = true
		}
	}
}

func TestChaCha20Poly1305WycheproofVectors(t *testing.T) {
	f, err := os.Open("../../../../wycheproof/testvectors/chacha20_poly1305_test.json")
	if err != nil {
		t.Fatalf("cannot open file: %s, make sure that github.com/google/wycheproof is in your gopath", err)
	}
	parser := json.NewDecoder(f)
	data := new(testdata)
	if err := parser.Decode(data); err != nil {
		t.Fatalf("cannot decode test data: %s", err)
	}

	for _, g := range data.TestGroups {
		if g.KeySize/8 != chacha20poly1305.KeySize {
			continue
		}
		if g.IvSize/8 != chacha20poly1305.NonceSize {
			continue
		}

		for _, tc := range g.Tests {
			key, err := hex.DecodeString(tc.Key)
			if err != nil {
				t.Errorf("#%d, cannot decode key: %s", tc.TcID, err)
			}
			aad, err := hex.DecodeString(tc.Aad)
			if err != nil {
				t.Errorf("#%d, cannot decode aad: %s", tc.TcID, err)
			}
			msg, err := hex.DecodeString(tc.Msg)
			if err != nil {
				t.Errorf("#%d, cannot decode msg: %s", tc.TcID, err)
			}
			ct, err := hex.DecodeString(tc.Ct)
			if err != nil {
				t.Errorf("#%d, cannot decode ct: %s", tc.TcID, err)
			}
			nonce, err := hex.DecodeString(tc.Iv)
			if err != nil {
				t.Errorf("#%d, cannot decode nonce: %s", tc.TcID, err)
			}
			tag, err := hex.DecodeString(tc.Tag)
			if err != nil {
				t.Errorf("#%d, cannot decode tag: %s", tc.TcID, err)
			}

			var combinedCt []byte
			combinedCt = append(combinedCt, nonce...)
			combinedCt = append(combinedCt, ct...)
			combinedCt = append(combinedCt, tag...)

			ca, err := aead.NewChaCha20Poly1305(key)
			if err != nil {
				t.Errorf("#%d, cannot create new instance of ChaCha20Poly1305: %s", tc.TcID, err)
				continue
			}

			_, err = ca.Encrypt(msg, aad)
			if err != nil {
				t.Errorf("#%d, unexpected encryption error: %s", tc.TcID, err)
				continue
			}

			decrypted, err := ca.Decrypt(combinedCt, aad)
			if err != nil {
				if tc.Result == "valid" {
					t.Errorf("#%d, unexpected error: %s", tc.TcID, err)
				}
			} else {
				if tc.Result == "invalid" {
					t.Errorf("#%d, decrypted invalid", tc.TcID)
				}
				if !bytes.Equal(decrypted, msg) {
					t.Errorf("#%d, incorrect decryption", tc.TcID)
				}
			}
		}
	}
}
