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

package subtle_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
)

func TestInsecureIvAesGcmCiphertextSize(t *testing.T) {
	for _, keySize := range keySizes {
		for _, prependIv := range []bool{true, false} {
			t.Run(fmt.Sprintf("keySize-%d/prependIv-%t", keySize, prependIv), func(t *testing.T) {
				key := random.GetRandomBytes(uint32(keySize))
				a, err := subtle.NewInsecureIvAesGcm(key, prependIv)
				if err != nil {
					t.Fatalf("NewInsecureIvAesGcm: got err %q, want success", err)
				}
				iv := random.GetRandomBytes(subtle.AESGCMIVSize)
				pt := random.GetRandomBytes(32)
				ad := random.GetRandomBytes(32)

				ct, err := a.Encrypt(iv, pt, ad)
				if err != nil {
					t.Fatalf("Encrypt: got err %q, want success", err)
				}

				wantSize := len(pt) + subtle.AESGCMTagSize
				if prependIv {
					wantSize += subtle.AESGCMIVSize
				}
				if len(ct) != wantSize {
					t.Errorf("unexpected ciphertext length: got %d, want %d", len(ct), wantSize)
				}
			})
		}
	}
}

func TestInsecureIvAesGcmKeySize(t *testing.T) {
	for _, keySize := range keySizes {
		for _, prependIv := range []bool{true, false} {
			t.Run(fmt.Sprintf("keySize-%d/prependIv-%t", keySize, prependIv), func(t *testing.T) {
				if _, err := subtle.NewInsecureIvAesGcm(make([]byte, keySize), prependIv); err != nil {
					t.Errorf("NewInsecureIvAesGcm: got err %q, want success", err)
				}
				if _, err := subtle.NewInsecureIvAesGcm(make([]byte, keySize+1), prependIv); err == nil {
					t.Error("NewInsecureIvAesGcm: got success, want err")
				}
				if _, err := subtle.NewInsecureIvAesGcm(make([]byte, keySize-1), prependIv); err == nil {
					t.Error("NewInsecureIvAesGcm: got success, want err")
				}
			})
		}
	}
}

func TestInsecureIvAesGcmIvMismatch(t *testing.T) {
	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("keySize-%d", keySize), func(t *testing.T) {
			key := random.GetRandomBytes(uint32(keySize))
			a, err := subtle.NewInsecureIvAesGcm(key, true /*=prependIv*/)
			if err != nil {
				t.Fatalf("NewInsecureIvAesGcm: got err %q, want success", err)
			}
			iv := random.GetRandomBytes(subtle.AESGCMIVSize)
			pt := random.GetRandomBytes(32)
			ad := random.GetRandomBytes(32)

			ct, err := a.Encrypt(iv, pt, ad)
			if err != nil {
				t.Fatalf("Encrypt: got err %q, want success", err)
			}

			newIv := iv
			randByte, randBit := rand.Intn(subtle.AESGCMIVSize), rand.Intn(8)
			newIv[randByte] ^= (1 << uint8(randBit))

			if _, err := a.Decrypt(newIv, ct, ad); err == nil {
				t.Error("Decrypt with wrong iv argument: want err, got success")
			}
			ctPrefixedWithNewIv := append(newIv, ct[subtle.AESGCMIVSize:]...)
			if _, err := a.Decrypt(iv, ctPrefixedWithNewIv, ad); err == nil {
				t.Error("Decrypt with ct prefixed with wrong IV: want err, got success")
			}
		})
	}
}

func TestInsecureIvAesGcm(t *testing.T) {
	for _, keySize := range keySizes {
		for _, prependIv := range []bool{true, false} {
			for ptSize := 0; ptSize < 75; ptSize++ {
				t.Run(fmt.Sprintf("keySize-%d/prependIv-%t/ptSize-%d", keySize, prependIv, ptSize), func(t *testing.T) {
					key := random.GetRandomBytes(uint32(keySize))
					a, err := subtle.NewInsecureIvAesGcm(key, prependIv)
					if err != nil {
						t.Fatalf("NewInsecureIvAesGcm: got err %q, want success", err)
					}
					iv := random.GetRandomBytes(subtle.AESGCMIVSize)
					pt := random.GetRandomBytes(uint32(ptSize))
					ad := random.GetRandomBytes(uint32(5))

					ct, err := a.Encrypt(iv, pt, ad)
					if err != nil {
						t.Fatalf("Encrypt: got err %q, want success", err)
					}

					got, err := a.Decrypt(iv, ct, ad)
					if err != nil {
						t.Fatalf("Decrypt: got err %q, want success", err)
					}
					if !bytes.Equal(got, pt) {
						t.Errorf("Decrypt: got %x, want %x", got, pt)
					}
				})
			}
		}
	}
}

func TestInsecureIvAesGcmLongPlaintext(t *testing.T) {
	for _, keySize := range keySizes {
		for _, prependIv := range []bool{true, false} {
			ptSize := 16
			for ptSize <= 1<<24 {
				t.Run(fmt.Sprintf("keySize-%d/prependIv-%t/ptSize-%d", keySize, prependIv, ptSize), func(t *testing.T) {
					key := random.GetRandomBytes(uint32(keySize))
					a, err := subtle.NewInsecureIvAesGcm(key, prependIv)
					if err != nil {
						t.Fatalf("NewInsecureIvAesGcm: got err %q, want success", err)
					}
					iv := random.GetRandomBytes(subtle.AESGCMIVSize)
					pt := random.GetRandomBytes(uint32(ptSize))
					ad := random.GetRandomBytes(uint32(ptSize / 3))

					ct, err := a.Encrypt(iv, pt, ad)
					if err != nil {
						t.Fatalf("Encrypt: got err %q, want success", err)
					}

					got, err := a.Decrypt(iv, ct, ad)
					if err != nil {
						t.Fatalf("Decrypt: got err %q, want success", err)
					}
					if !bytes.Equal(got, pt) {
						t.Errorf("Decrypt: got %x, want %x", got, pt)
					}
				})
				ptSize += 5 * ptSize / 11
			}
		}
	}
}

func TestInsecureIvAesGcmModifyCiphertext(t *testing.T) {
	key := random.GetRandomBytes(16)
	for _, prependIv := range []bool{true, false} {
		t.Run(fmt.Sprintf("prependIv-%t", prependIv), func(t *testing.T) {
			a, err := subtle.NewInsecureIvAesGcm(key, prependIv)
			if err != nil {
				t.Fatalf("NewInsecureIvAesGcm: got err %q, want success", err)
			}
			iv := random.GetRandomBytes(subtle.AESGCMIVSize)
			pt := random.GetRandomBytes(32)
			ad := random.GetRandomBytes(33)
			ct, err := a.Encrypt(iv, pt, ad)
			if err != nil {
				t.Fatalf("Encrypt: got err %q, want success", err)
			}

			// Flip bits.
			for i := 0; i < len(ct); i++ {
				tmpCt := ct[i]
				for j := 0; j < 8; j++ {
					ct[i] ^= 1 << uint8(j)
					tmpIv := iv
					if prependIv {
						tmpIv = ct[:subtle.AESGCMIVSize]
					}
					if _, err := a.Decrypt(tmpIv, ct, ad); err == nil {
						t.Errorf("ciphertext with flipped byte %d, bit %d: expected err, got success", i, j)
					}
					ct[i] = tmpCt
				}
			}

			// Truncate ciphertext.
			for i := 1; i < len(ct); i++ {
				if _, err := a.Decrypt(iv, ct[:i], ad); err == nil {
					t.Errorf("ciphertext truncated to byte %d: expected err, got success", i)
				}
			}

			// Modify associated data.
			for i := 0; i < len(ad); i++ {
				tmp := ad[i]
				for j := 0; j < 8; j++ {
					ad[i] ^= 1 << uint8(j)
					if _, err := a.Decrypt(iv, ct, ad); err == nil {
						t.Errorf("associated data with flipped byte %d, bit %d: expected err, got success", i, j)
					}
					ad[i] = tmp
				}
			}
		})
	}
}

type aeadSuite struct {
	testutil.WycheproofSuite
	TestGroups []*aeadGroup `json:"testGroups"`
}

type aeadGroup struct {
	testutil.WycheproofGroup
	IvSize  uint32      `json:"ivSize"`
	KeySize uint32      `json:"keySize"`
	TagSize uint32      `json:"tagSize"`
	Type    string      `json:"type"`
	Tests   []*aeadCase `json:"tests"`
}

type aeadCase struct {
	testutil.WycheproofCase
	Ad  testutil.HexBytes `json:"aad"`
	Ct  testutil.HexBytes `json:"ct"`
	Iv  testutil.HexBytes `json:"iv"`
	Key testutil.HexBytes `json:"key"`
	Msg testutil.HexBytes `json:"msg"`
	Tag testutil.HexBytes `json:"tag"`
}

func TestInsecureIvAesGcmWycheproofVectors(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)

	suite := new(aeadSuite)
	if err := testutil.PopulateSuite(suite, "aes_gcm_test.json"); err != nil {
		t.Fatalf("failed to populate suite: %s", err)
	}
	for _, group := range suite.TestGroups {
		if err := subtle.ValidateAESKeySize(group.KeySize / 8); err != nil {
			continue
		}
		if group.IvSize != subtle.AESGCMIVSize*8 {
			continue
		}
		for _, tc := range group.Tests {
			name := fmt.Sprintf("%s-%s(%d,%d)/Case-%d", suite.Algorithm, group.Type, group.KeySize, group.TagSize, tc.CaseID)
			t.Run(name, func(t *testing.T) {
				a, err := subtle.NewInsecureIvAesGcm(tc.Key, false /*=prependIv*/)
				if err != nil {
					t.Fatalf("NewInsecureIvAesGcm: got err %q, want success", err)
				}

				var combinedCt []byte
				combinedCt = append(combinedCt, tc.Ct...)
				combinedCt = append(combinedCt, tc.Tag...)

				got, err := a.Decrypt(tc.Iv, combinedCt, tc.Ad)
				if err != nil {
					if tc.Result == "valid" {
						t.Errorf("Decrypt: got err %q, want success", err)
					}
				} else {
					if tc.Result == "invalid" {
						t.Error("Decrypt: got success, want error")
					}
					if !bytes.Equal(got, tc.Msg) {
						t.Errorf("Decrypt: got %x, want %x", got, tc.Msg)
					}
				}
			})
		}
	}
}
