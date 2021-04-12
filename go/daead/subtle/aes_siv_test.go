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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/tink/go/daead/subtle"
	"github.com/google/tink/go/subtle/random"
)

type testData struct {
	Algorithm        string
	GeneratorVersion string
	NumberOfTests    uint32
	TestGroups       []*testGroup
}

type testGroup struct {
	KeySize uint32
	Type    string
	Tests   []*testCase
}

type testCase struct {
	TcID   uint32
	Key    string
	Aad    string
	Msg    string
	Ct     string
	Result string
}

func TestAESSIV_EncryptDecrypt(t *testing.T) {
	keyStr :=
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	key, _ := hex.DecodeString(keyStr)
	msg := []byte("Some data to encrypt.")
	aad := []byte("Additional data")

	a, err := subtle.NewAESSIV(key)
	if err != nil {
		t.Errorf("NewAESSIV(key) = _, %v, want _, nil", err)
	}

	ct, err := a.EncryptDeterministically(msg, aad)
	if err != nil {
		t.Errorf("Unexpected encryption error: %v", err)
	}

	if pt, err := a.DecryptDeterministically(ct, aad); err != nil {
		t.Errorf("Unexpected decryption error: %v", err)
	} else if !bytes.Equal(pt, msg) {
		t.Errorf("Mismatched plaintexts: got %v, want %v", pt, msg)
	}
}

func TestAESSIV_EmptyPlaintext(t *testing.T) {
	keyStr :=
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	key, _ := hex.DecodeString(keyStr)
	aad := []byte("Additional data")

	a, err := subtle.NewAESSIV(key)
	if err != nil {
		t.Errorf("NewAESSIV(key) = _, %v, want _, nil", err)
	}

	ct, err := a.EncryptDeterministically(nil, aad)
	if err != nil {
		t.Errorf("Unexpected encryption error: %v", err)
	}
	if pt, err := a.DecryptDeterministically(ct, aad); err != nil {
		t.Errorf("Unexpected decryption error: %v", err)
	} else if !bytes.Equal(pt, []byte{}) {
		t.Errorf("Mismatched plaintexts: got %v, want []", pt)
	}

	ct, err = a.EncryptDeterministically([]byte{}, aad)
	if err != nil {
		t.Errorf("Unexpected encryption error: %v", err)
	}
	if pt, err := a.DecryptDeterministically(ct, aad); err != nil {
		t.Errorf("Unexpected decryption error: %v", err)
	} else if !bytes.Equal(pt, []byte{}) {
		t.Errorf("Mismatched plaintexts: got %v, want []", pt)
	}
}

func TestAESSIV_EmptyAdditionalData(t *testing.T) {
	keyStr :=
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	key, _ := hex.DecodeString(keyStr)

	a, err := subtle.NewAESSIV(key)
	if err != nil {
		t.Errorf("NewAESSIV(key) = _, %v, want _, nil", err)
	}

	ct, err := a.EncryptDeterministically(nil, nil)
	if err != nil {
		t.Errorf("Unexpected encryption error: %v", err)
	}

	if pt, err := a.DecryptDeterministically(ct, nil); err != nil {
		t.Errorf("Unexpected decryption error: %v", err)
	} else if !bytes.Equal(pt, []byte{}) {
		t.Errorf("Mismatched plaintexts: got %v, want []", pt)
	}

	if pt, err := a.DecryptDeterministically(ct, []byte{}); err != nil {
		t.Errorf("Unexpected decryption error: %v", err)
	} else if !bytes.Equal(pt, []byte{}) {
		t.Errorf("Mismatched plaintexts: got %v, want []", pt)
	}
}

func TestAESSIV_KeySizes(t *testing.T) {
	keyStr :=
		"198371900187498172316311acf81d238ff7619873a61983d619c87b63a1987f" +
			"987131819803719b847126381cd763871638aa71638176328761287361231321" +
			"812731321de508761437195ff231765aa4913219873ac6918639816312130011" +
			"abc900bba11400187984719827431246bbab1231eb4145215ff7141436616beb" +
			"9817298148712fed3aab61000ff123313e"
	key, _ := hex.DecodeString(keyStr)

	for i := 0; i < len(key); i++ {
		_, err := subtle.NewAESSIV(key[:i])
		if i == subtle.AESSIVKeySize && err != nil {
			t.Errorf("Rejected valid key size: %v, %v", i, err)
		}
		if i != subtle.AESSIVKeySize && err == nil {
			t.Errorf("Allowed invalid key size: %v", i)
		}
	}
}

func TestAESSIV_MessageSizes(t *testing.T) {
	keyStr :=
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	key, _ := hex.DecodeString(keyStr)
	aad := []byte("Additional data")

	a, err := subtle.NewAESSIV(key)
	if err != nil {
		t.Errorf("NewAESSIV(key) = _, %v, want _, nil", err)
	}

	for i := uint32(0); i < 1024; i++ {
		msg := random.GetRandomBytes(i)
		ct, err := a.EncryptDeterministically(msg, aad)
		if err != nil {
			t.Errorf("Unexpected encryption error: %v", err)
		}
		if pt, err := a.DecryptDeterministically(ct, aad); err != nil {
			t.Errorf("Unexpected decryption error: %v", err)
		} else if !bytes.Equal(pt, msg) {
			t.Errorf("Mismatched plaintexts: got %v, want %v", pt, msg)
		}
	}

	for i := uint32(1024); i < 100000; i += 5000 {
		msg := random.GetRandomBytes(i)
		ct, err := a.EncryptDeterministically(msg, aad)
		if err != nil {
			t.Errorf("Unexpected encryption error: %v", err)
		}
		if pt, err := a.DecryptDeterministically(ct, aad); err != nil {
			t.Errorf("Unexpected decryption error: %v", err)
		} else if !bytes.Equal(pt, msg) {
			t.Errorf("Mismatched plaintexts: got %v, want %v", pt, msg)
		}
	}
}

func TestAESSIV_AdditionalDataSizes(t *testing.T) {
	keyStr :=
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	key, _ := hex.DecodeString(keyStr)
	msg := []byte("Some data to encrypt.")

	a, err := subtle.NewAESSIV(key)
	if err != nil {
		t.Errorf("NewAESSIV(key) = _, %v, want _, nil", err)
	}

	for i := uint32(0); i < 1024; i++ {
		aad := random.GetRandomBytes(i)
		ct, err := a.EncryptDeterministically(msg, aad)
		if err != nil {
			t.Errorf("Unexpected encryption error: %v", err)
		}
		if pt, err := a.DecryptDeterministically(ct, aad); err != nil {
			t.Errorf("Unexpected decryption error: %v", err)
		} else if !bytes.Equal(pt, msg) {
			t.Errorf("Mismatched plaintexts: got %v, want %v", pt, msg)
		}
	}
}

func TestAESSIV_CiphertextModifications(t *testing.T) {
	keyStr :=
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	key, _ := hex.DecodeString(keyStr)
	aad := []byte("Additional data")

	a, err := subtle.NewAESSIV(key)
	if err != nil {
		t.Errorf("NewAESSIV(key) = _, %v, want _, nil", err)
	}

	for i := uint32(0); i < 50; i++ {
		msg := random.GetRandomBytes(i)
		ct, err := a.EncryptDeterministically(msg, aad)
		if err != nil {
			t.Errorf("Unexpected encryption error: %v", err)
		}
		for j := 0; j < len(ct); j++ {
			for b := uint32(0); b < 8; b++ {
				ct[j] ^= 1 << b
				if _, err := a.DecryptDeterministically(ct, aad); err == nil {
					t.Errorf("Modified ciphertext decrypted: byte %d, bit %d", j, b)
				}
				ct[j] ^= 1 << b
			}
		}
	}
}

func TestAESSIV_WycheproofVectors(t *testing.T) {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}
	f, err := os.Open(filepath.Join(srcDir, "wycheproof/testvectors/aes_siv_cmac_test.json"))
	if err != nil {
		t.Fatalf("Cannot open file: %s", err)
	}
	parser := json.NewDecoder(f)
	data := new(testData)
	if err := parser.Decode(data); err != nil {
		t.Fatalf("Cannot decode test data: %s", err)
	}

	for _, g := range data.TestGroups {
		if g.KeySize/8 != subtle.AESSIVKeySize {
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

			a, err := subtle.NewAESSIV(key)
			if err != nil {
				t.Errorf("NewAESSIV(key) = _, %v, want _, nil", err)
				continue
			}

			// EncryptDeterministically should always succeed since msg and aad are valid inputs.
			gotCt, err := a.EncryptDeterministically(msg, aad)
			if err != nil {
				t.Errorf("#%d, unexpected encryption error: %v", tc.TcID, err)
			} else {
				if tc.Result == "valid" && !bytes.Equal(gotCt, ct) {
					t.Errorf("#%d, incorrect encryption: got %v, want %v", tc.TcID, gotCt, ct)
				}
				if tc.Result == "invalid" && bytes.Equal(gotCt, ct) {
					t.Errorf("#%d, invalid encryption: got %v, want %v", tc.TcID, gotCt, ct)
				}
			}

			pt, err := a.DecryptDeterministically(ct, aad)
			if tc.Result == "valid" {
				if err != nil {
					t.Errorf("#%d, unexpected decryption error: %v", tc.TcID, err)
				} else if !bytes.Equal(pt, msg) {
					t.Errorf("#%d, incorrect decryption: got %v, want %v", tc.TcID, pt, msg)
				}
			} else {
				if err == nil {
					t.Errorf("#%d, decryption error expected: got nil", tc.TcID)
				}
			}
		}
	}
}
