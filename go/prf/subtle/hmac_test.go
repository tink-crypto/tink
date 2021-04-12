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
	"strings"
	"testing"

	"github.com/google/tink/go/prf/subtle"
	"github.com/google/tink/go/testutil"
)

type rfc4868test struct {
	key  string
	data string
	prf  map[string]string
}

func TestVectorsRFC4868(t *testing.T) {
	// Test vectors from RFC 4868.
	testvectors := []*rfc4868test{
		{
			key:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			data: "4869205468657265",
			prf: map[string]string{
				"SHA256": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
				"SHA512": "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
			},
		},
		{
			key:  "4a656665",
			data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			prf: map[string]string{
				"SHA256": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
				"SHA512": "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
			},
		},
		{
			key:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			data: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			prf: map[string]string{
				"SHA256": "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
				"SHA512": "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
			},
		},
		{
			key:  "0102030405060708090a0b0c0d0e0f10111213141516171819",
			data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			prf: map[string]string{
				"SHA256": "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
				"SHA512": "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
			},
		},
		{
			key:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			data: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
			prf: map[string]string{
				"SHA256": "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
				"SHA512": "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
			},
		},
		{
			key:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			data: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
			prf: map[string]string{
				"SHA256": "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
				"SHA512": "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
			},
		},
	}
	for _, v := range testvectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Errorf("Could not decode key: %v", err)
		}
		data, err := hex.DecodeString(v.data)
		if err != nil {
			t.Errorf("Could not decode data: %v", err)
		}
		for hash, e := range v.prf {
			h, err := subtle.NewHMACPRF(hash, key)
			if err != nil {
				t.Errorf("Could not create HMAC PRF object: %v", err)
			}
			output, err := h.ComputePRF(data, uint32(len(e)/2))
			if err != nil {
				t.Errorf("Error computing HMAC: %v", err)
			}
			if hex.EncodeToString(output) != e {
				t.Errorf("Computation and test vector differ. Computation: %q, Test Vector %q", hex.EncodeToString(output), e)
			}
		}
	}
}

func TestHMACPRFWycheproofCases(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	for _, hash := range []string{"SHA1", "SHA256", "SHA512"} {
		filename := fmt.Sprintf("hmac_%s_test.json", strings.ToLower(hash))
		suite := new(macSuite)
		if err := testutil.PopulateSuite(suite, filename); err != nil {
			t.Fatalf("Failed populating suite: %s", err)
		}
		for _, group := range suite.TestGroups {
			groupName := fmt.Sprintf("%s-%s-%s(%d)", suite.Algorithm, group.Type, hash, group.KeySize)
			if group.TagSize%8 != 0 {
				t.Errorf("For %s, requested tag size is not a multiple of 8, but %d", groupName, group.TagSize)
			}

			for _, test := range group.Tests {
				caseName := fmt.Sprintf("%s:Case-%d", groupName, test.CaseID)
				t.Run(caseName, func(t *testing.T) {

					h, err := subtle.NewHMACPRF(hash, test.Key)
					switch test.Result {
					case "valid":
						if err != nil {
							t.Fatalf("NewHMACPRF() failed: %v", err)
						}
						res, err := h.ComputePRF(test.Message, group.TagSize/8)
						if err != nil {
							t.Fatalf("ComputePRF() failed: %v", err)
						}
						if !bytes.Equal(res, test.Tag) {
							t.Errorf("ComputePRF() result and expected result do not match:\nComputed: %q\nExpected: %q", hex.EncodeToString(res), hex.EncodeToString(test.Tag))
						}

					case "invalid":
						if err != nil {
							return
						}
						res, err := h.ComputePRF(test.Message, group.TagSize/8)
						if err != nil {
							return
						}
						if bytes.Equal(res, test.Tag) {
							t.Errorf("ComputePRF() result and invalid expected result match:\nComputed: %q\nExpected: %q", hex.EncodeToString(res), hex.EncodeToString(test.Tag))
						}

					default:
						t.Fatalf("Unsupported test result: %q", test.Result)
					}
				})
			}
		}
	}
}

func TestHMACPRFHash(t *testing.T) {
	if _, err := subtle.NewHMACPRF("SHA256", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}); err != nil {
		t.Errorf("Expected NewHMACPRF to work with SHA256: %v", err)
	}
	if _, err := subtle.NewHMACPRF("SHA512", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}); err != nil {
		t.Errorf("Expected NewHMACPRF to work with SHA512: %v", err)
	}
	if _, err := subtle.NewHMACPRF("SHA1", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}); err != nil {
		t.Errorf("Expected NewHMACPRF to work with SHA1: %v", err)
	}
	if _, err := subtle.NewHMACPRF("md5", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}); err == nil {
		t.Errorf("Expected NewHMACPRF to fail with md5")
	}
}

func TestHMACPRFOutputLength(t *testing.T) {
	for hash, length := range map[string]int{"SHA1": 20, "SHA256": 32, "SHA512": 64} {
		prf, err := subtle.NewHMACPRF(hash, []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
		if err != nil {
			t.Errorf("Expected NewHMACPRF to work on 32 byte key with hash %s", hash)
		}
		for i := 0; i <= length; i++ {
			output, err := prf.ComputePRF([]byte{0x01, 0x02}, uint32(i))
			if err != nil {
				t.Errorf("Expected to be able to compute HMAC %s PRF with %d output length", hash, i)
			}
			if len(output) != i {
				t.Errorf("Expected HMAC %s PRF to compute %d bytes, got %d", hash, i, len(output))
			}
		}
		for i := length + 1; i < 100; i++ {
			_, err := prf.ComputePRF([]byte{0x01, 0x02}, uint32(i))
			if err == nil {
				t.Errorf("Expected to not be able to compute HMAC %s PRF with %d output length", hash, i)
			}
		}
	}
}

func TestValidateHMACPRFParams(t *testing.T) {
	if err := subtle.ValidateHMACPRFParams("SHA256", 32); err != nil {
		t.Errorf("Unexpected error for valid HMAC PRF params: %v", err)
	}
	if err := subtle.ValidateHMACPRFParams("SHA256", 4); err == nil {
		t.Errorf("Short key size not detected for HMAC PRF params")
	}
	if err := subtle.ValidateHMACPRFParams("md5", 32); err == nil {
		t.Errorf("Weak hash function not detected for HMAC PRF params")
	}
}
