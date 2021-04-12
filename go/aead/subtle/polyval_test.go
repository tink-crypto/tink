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
	"testing"

	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/subtle/random"
)

// These test vectors have been taken from Appendix C in go/rfc/8452.
var testVectors = []struct {
	Key, Input, Hash string
}{
	{ // Test Case 0
		Key:   "25629347589242761d31f826ba4b757b",
		Input: "4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362",
		Hash:  "f7a3b47b846119fae5b7866cf5e5b77e",
	},
	{ // Test Case 1
		Key:   "d9b360279694941ac5dbc6987ada7377",
		Input: "00000000000000000000000000000000",
		Hash:  "00000000000000000000000000000000",
	},
	{ // Test Case 2
		Key:   "d9b360279694941ac5dbc6987ada7377",
		Input: "01000000000000000000000000000000000000000000000040",
		Hash:  "eb93b7740962c5e49d2a90a7dc5cec74",
	},
	{ // Test Case 3
		Key:   "d9b360279694941ac5dbc6987ada7377",
		Input: "01000000000000000000000000000000000000000000000060",
		Hash:  "48eb6c6c5a2dbe4a1dde508fee06361b",
	},
	{ // Test Case 4
		Key:   "d9b360279694941ac5dbc6987ada7377",
		Input: "01000000000000000000000000000000000000000000000080",
		Hash:  "20806c26e3c1de019e111255708031d6",
	},
	{ // Test Case 5
		Key:   "d9b360279694941ac5dbc6987ada7377",
		Input: "010000000000000000000000000000000200000000000000000000000000000000000000000000000001",
		Hash:  "ce6edc9a50b36d9a98986bbf6a261c3b",
	},
	{ // Test Case 6
		Key:   "0533fd71f4119257361a3ff1469dd4e5",
		Input: "489c8fde2be2cf97e74e932d4ed87d00c9882e5386fd9f92ec00000000000000780000000000000048",
		Hash:  "bf160bc9ded8c63057d2c38aae552fb4",
	},
	{ // Test Case 7
		Key:   "64779ab10ee8a280272f14cc8851b727",
		Input: "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f0000000000000000000000001db2316fd568378da107b52b00000000a00000000000000060",
		Hash:  "cc86ee22c861e1fd474c84676b42739c",
	},
	{ // Test Case 8
		Key:   "27c2959ed4daea3b1f52e849478de376",
		Input: "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f0000000000000021702de0de18baa9c9596291b0846600c80000000000000078",
		Hash:  "c4fa5e5b713853703bcf8e6424505fa5",
	},
	{ // Test Case 9
		Key:   "670b98154076ddb59b7a9137d0dcc0f0",
		Input: "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac70000b202b370ef9768ec6561c4fe6b7e7296fa850000000000000000000000000000f00000000000000090",
		Hash:  "4e4108f09f41d797dc9256f8da8d58c7",
	},
	{ // Test Case 10
		Key:   "cb8c3aa3f8dbaeb4b28a3e86ff6625f8",
		Input: "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f16754100000000000000000000000000ced532ce4159b035277d4dfbb7db62968b13cd4eec00000000000000000000001801000000000000a8",
		Hash:  "ffd503c7dd712eb3791b7114b17bb0cf",
	},
}

func TestPolyval(t *testing.T) {
	for id, tc := range testVectors {
		key, err := hex.DecodeString(tc.Key)
		if err != nil {
			t.Errorf("cannot decode key in test case %d: %s", id, err)
			continue
		}
		input, err := hex.DecodeString(tc.Input)
		if err != nil {
			t.Errorf("cannot decode aad in test case %d: %s", id, err)
			continue
		}
		expectedHash, err := hex.DecodeString(tc.Hash)
		if err != nil {
			t.Errorf("cannot decode msg in test case %d: %s", id, err)
			continue
		}

		p, err := subtle.NewPolyval(key)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
			continue
		}

		p.Update(input)
		hash := p.Finish()
		actualHash := hash[:]

		if !bytes.Equal(actualHash, expectedHash) {
			t.Errorf("Hash values don't match in test case %d: actual %s, expected %s",
				id, hex.EncodeToString(actualHash), hex.EncodeToString(expectedHash))
		}
	}
}

func TestPolyvalRejectsInvalidKeyLength(t *testing.T) {
	invalidKeySizes := []uint32{4, 8, 12, 15, 17, 24, 32}

	for id, keySize := range invalidKeySizes {
		key := random.GetRandomBytes(keySize)

		_, err := subtle.NewPolyval(key)
		if err == nil {
			t.Errorf("Expected error with invalid key-size %d case %d", keySize, id)
		}
	}
}
