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
////////////////////////////////////////////////////////////////////////////////

package streamingprf

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
)

func TestNewHKDFStreamingPRF(t *testing.T) {
	for _, test := range []struct {
		name string
		hash string
		salt []byte
	}{
		{"SHA256, nil salt", "SHA256", nil},
		{"SHA256, random salt", "SHA256", random.GetRandomBytes(16)},
		{"SHA512, nil salt", "SHA512", nil},
		{"SHA512, random salt", "SHA512", random.GetRandomBytes(16)},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := random.GetRandomBytes(32)
			h, err := newHKDFStreamingPRF(test.hash, key, test.salt)
			if err != nil {
				t.Fatalf("newHKDFStreamingPRF() err = %v, want nil", err)
			}
			if !bytes.Equal(h.key, key) {
				t.Errorf("key = %v, want %v", h.key, key)
			}
			if !bytes.Equal(h.salt, test.salt) {
				t.Errorf("salt = %v, want %v", h.salt, test.salt)
			}
		})
	}
}

func TestNewHKDFStreamingPRFFails(t *testing.T) {
	for _, test := range []struct {
		hash    string
		keySize uint32
	}{
		{"SHA256", 16},
		{"SHA512", 16},
		{"SHA1", 20},
	} {
		t.Run(test.hash, func(t *testing.T) {
			if _, err := newHKDFStreamingPRF(test.hash, random.GetRandomBytes(test.keySize), nil); err == nil {
				t.Error("newHKDFStreamingPRF() err = nil, want non-nil")
			}
		})
	}
}

func TestHKDFStreamingPRFWithRFCVector(t *testing.T) {
	// This is the only vector that uses an accepted hash function and has key
	// size >= minHKDFStreamingPRFKeySize.
	// https://www.rfc-editor.org/rfc/rfc5869#appendix-A.2
	vec := struct {
		hash   string
		key    string
		salt   string
		info   string
		outLen int
		okm    string
	}{
		hash:   "SHA256",
		key:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		salt:   "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		info:   "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		outLen: 82,
		okm:    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
	}
	key, err := hex.DecodeString(vec.key)
	if err != nil {
		t.Fatalf("hex.DecodeString err = %v, want nil", err)
	}
	salt, err := hex.DecodeString(vec.salt)
	if err != nil {
		t.Fatalf("hex.DecodeString err = %v, want nil", err)
	}
	info, err := hex.DecodeString(vec.info)
	if err != nil {
		t.Fatalf("hex.DecodeString err = %v, want nil", err)
	}

	h, err := newHKDFStreamingPRF(vec.hash, key, salt)
	if err != nil {
		t.Fatalf("newHKDFStreamingPRF() err = %v, want nil", err)
	}
	r := h.Compute(info)
	out := make([]byte, vec.outLen)
	if _, err := io.ReadAtLeast(r, out, len(out)); err != nil {
		t.Fatalf("io.ReadAtLeast err = %v, want nil", err)
	}
	if hex.EncodeToString(out) != vec.okm {
		t.Errorf("Compute() = %v, want %v", hex.EncodeToString(out), vec.okm)
	}
}

func TestHKDFStreamingPRFWithWycheproof(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)

	type hkdfCase struct {
		testutil.WycheproofCase
		IKM  testutil.HexBytes `json:"ikm"`
		Salt testutil.HexBytes `json:"salt"`
		Info testutil.HexBytes `json:"info"`
		Size uint32            `json:"size"`
		OKM  testutil.HexBytes `json:"okm"`
	}
	type hkdfGroup struct {
		testutil.WycheproofGroup
		KeySize uint32      `json:"keySize"`
		Type    string      `json:"type"`
		Tests   []*hkdfCase `json:"tests"`
	}
	type hkdfSuite struct {
		testutil.WycheproofSuite
		TestGroups []*hkdfGroup `json:"testGroups"`
	}

	count := 0
	for _, hash := range []string{"SHA256", "SHA512"} {
		filename := fmt.Sprintf("hkdf_%s_test.json", strings.ToLower(hash))
		suite := new(hkdfSuite)
		if err := testutil.PopulateSuite(suite, filename); err != nil {
			t.Fatalf("testutil.PopulateSuite(%v, %s): %v", suite, filename, err)
		}
		for _, group := range suite.TestGroups {
			for _, test := range group.Tests {
				caseName := fmt.Sprintf("%s(%d):Case-%d", hash, group.KeySize, test.CaseID)
				t.Run(caseName, func(t *testing.T) {
					if got, want := len(test.IKM), int(group.KeySize/8); got != want {
						t.Fatalf("invalid key length = %d, want %d", got, want)
					}
					count++

					h, err := newHKDFStreamingPRF(hash, test.IKM, test.Salt)
					switch test.Result {
					case "valid":
						if len(test.IKM) < minHKDFStreamingPRFKeySize {
							if err == nil {
								t.Error("newHKDFStreamingPRF err = nil, want non-nil")
							}
							return
						}
						if err != nil {
							t.Fatalf("newHKDFStreamingPRF err = %v, want nil", err)
						}
						r := h.Compute(test.Info)
						out := make([]byte, test.Size)
						if _, err := io.ReadAtLeast(r, out, len(out)); err != nil {
							t.Fatalf("io.ReadAtLeast err = %v, want nil", err)
						}
						if !bytes.Equal(out, test.OKM) {
							t.Errorf("Compute() = %v, want %v", out, test.OKM)
						}

					case "invalid":
						if err != nil {
							return
						}
						r := h.Compute(test.Info)
						out := make([]byte, test.Size)
						if _, err := io.ReadAtLeast(r, out, len(out)); err == nil {
							t.Error("io.ReadAtLeast err = nil, want non-nil")
						}

					default:
						t.Errorf("unsupported test result: %s", test.Result)
					}
				})
			}
		}
	}
	if count < 200 {
		t.Errorf("number of test cases = %d, want > 200", count)
	}
}
