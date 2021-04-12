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

package subtle

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/google/tink/go/subtle/random"
)

// Tests the implementation against the test vectors from RFC 5869.
var hkdfTests = []struct {
	hashAlg     string
	key         string
	salt        string
	info        string
	tagSize     uint32
	expectedKDF string
}{
	{
		hashAlg:     "SHA256",
		key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt:        "000102030405060708090a0b0c",
		info:        "f0f1f2f3f4f5f6f7f8f9",
		tagSize:     42,
		expectedKDF: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
	},
	{
		hashAlg: "SHA256",
		key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f",
		salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
			"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
			"d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		tagSize: 82,
		expectedKDF: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
			"59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
			"cc30c58179ec3e87c14c01d5c1f3434f1d87",
	},
	{
		hashAlg: "SHA256",
		key:     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt:    "",
		info:    "",
		tagSize: 42,
		expectedKDF: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d" +
			"9d201395faa4b61a96c8",
	},
	{
		hashAlg:     "SHA1",
		key:         "0b0b0b0b0b0b0b0b0b0b0b",
		salt:        "000102030405060708090a0b0c",
		info:        "f0f1f2f3f4f5f6f7f8f9",
		tagSize:     42,
		expectedKDF: "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
	},
	{
		hashAlg: "SHA1",
		key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f",
		salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
			"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
			"d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		tagSize: 82,
		expectedKDF: "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe" +
			"8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e" +
			"927336d0441f4c4300e2cff0d0900b52d3b4",
	},
	{
		hashAlg: "SHA1",
		key:     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt:    "",
		info:    "",
		tagSize: 42,
		expectedKDF: "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0" +
			"ea00033de03984d34918",
	},
	{
		hashAlg: "SHA1",
		key:     "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
		salt:    "",
		info:    "",
		tagSize: 42,
		expectedKDF: "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5" +
			"673a081d70cce7acfc48",
	},
}

func TestHKDFBasic(t *testing.T) {
	for ti, test := range hkdfTests {
		k, _ := hex.DecodeString(test.key)
		s, _ := hex.DecodeString(test.salt)
		i, _ := hex.DecodeString(test.info)

		result, err := ComputeHKDF(test.hashAlg, k, s, i, test.tagSize)
		r := hex.EncodeToString(result)
		fmt.Printf("Test no: %d\n", ti)
		fmt.Printf("Length of tag :%d\n", test.tagSize)
		fmt.Printf("Length of result :%d\n", len(r))
		fmt.Printf("Length of expected :%d\n\n\n", len(test.expectedKDF))
		if err != nil {
			t.Errorf("mac computation failed in test case %d: %s", ti, err)
		}
		if r != test.expectedKDF {
			t.Errorf("incorrect hkdf in test case %d: expect %s, got %s",
				ti, test.expectedKDF, r)
		}
	}
}

func TestNewHMACWithInvalidInput(t *testing.T) {
	// invalid hash algorithm
	_, err := ComputeHKDF("SHA0", random.GetRandomBytes(16), nil, nil, 32)
	if err == nil || !strings.Contains(err.Error(), "invalid hash algorithm") {
		t.Errorf("expect an error when hash algorithm is invalid")
	}
	// tag too short
	_, err = ComputeHKDF("SHA256", random.GetRandomBytes(16), nil, nil, 9)
	if err == nil || !strings.Contains(err.Error(), "tag size too small") {
		t.Errorf("expect an error when tag size is too small")
	}
	// tag too big
	_, err = ComputeHKDF("SHA1", random.GetRandomBytes(16), nil, nil, 5101)
	if err == nil || !strings.Contains(err.Error(), "tag size too big") {
		t.Errorf("expect an error when tag size is too big")
	}
	_, err = ComputeHKDF("SHA256", random.GetRandomBytes(16), nil, nil, 8162)
	if err == nil || !strings.Contains(err.Error(), "tag size too big") {
		t.Errorf("expect an error when tag size is too big")
	}
	_, err = ComputeHKDF("SHA512", random.GetRandomBytes(16), nil, nil, 16323)
	if err == nil || !strings.Contains(err.Error(), "tag size too big") {
		t.Errorf("expect an error when tag size is too big")
	}
}
