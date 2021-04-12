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

	"github.com/google/tink/go/prf/subtle"
	"github.com/google/tink/go/testutil"
)

func TestVectorsRFC4493(t *testing.T) {
	// Test vectors from RFC 4493.
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	if err != nil {
		t.Errorf("Could not decode key: %v", err)
	}
	data, err := hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	if err != nil {
		t.Errorf("Could not decode data: %v", err)
	}
	expected := map[int]string{
		0:  "bb1d6929e95937287fa37d129b756746",
		16: "070a16b46b4d4144f79bdd9dd04a287c",
		40: "dfa66747de9ae63030ca32611497c827",
		64: "51f0bebf7e3b9d92fc49741779363cfe",
	}
	a, err := subtle.NewAESCMACPRF(key)
	if err != nil {
		t.Errorf("Could not create cmac.AES object: %v", err)
	}
	for l, e := range expected {
		output, err := a.ComputePRF(data[:l], 16)
		if err != nil {
			t.Errorf("Error computing AES-CMAC: %v", err)
		}
		if hex.EncodeToString(output) != e {
			t.Errorf("Computation and test vector differ. Computation: %q, Test Vector %q", hex.EncodeToString(output), e)
		}
	}
}

func TestAESCMACPRFWycheproofCases(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	suite := new(macSuite)
	if err := testutil.PopulateSuite(suite, "aes_cmac_test.json"); err != nil {
		t.Fatalf("Failed populating suite: %s", err)
	}
	for _, group := range suite.TestGroups {
		groupName := fmt.Sprintf("%s-%s(%d)", suite.Algorithm, group.Type, group.KeySize)
		if group.TagSize%8 != 0 {
			t.Errorf("For %s, requested tag size is not a multiple of 8, but %d", groupName, group.TagSize)
			continue
		}

		for _, test := range group.Tests {
			caseName := fmt.Sprintf("%s:Case-%d", groupName, test.CaseID)
			t.Run(caseName, func(t *testing.T) {
				if uint32(len(test.Key))*8 != group.KeySize {
					t.Fatalf("Invalid key length: %s", test.Comment)
				}

				aes, err := subtle.NewAESCMACPRF(test.Key)
				switch test.Result {
				case "valid":
					if err != nil {
						t.Fatalf("NewAESCMACPRF failed (case: %s):  %v", test.Comment, err)
					}
					res, err := aes.ComputePRF(test.Message, group.TagSize/8)
					if err != nil {
						t.Fatalf("ComputePRF() failed: %v", err)
					}
					if !bytes.Equal(res, test.Tag) {
						t.Errorf("ComputePRF() result and expected result do not match:\nComputed: %q\nExpected: %q", hex.EncodeToString(res), test.Tag)
					}

				case "invalid":
					if err != nil {
						return
					}
					res, err := aes.ComputePRF(test.Message, group.TagSize/8)
					if err != nil {
						return
					}
					if bytes.Equal(res, test.Tag) {
						t.Errorf("ComputePRF() result and invalid expected result match:\nComputed: %q\nExpected: %q", hex.EncodeToString(res), test.Tag)
					}

				default:
					t.Fatalf("Unsupported test result: %q", test.Result)
				}
			})
		}
	}
}

func TestValidateAESCMACPRFParams(t *testing.T) {
	if err := subtle.ValidateAESCMACPRFParams(32); err != nil {
		t.Errorf("Unexpected error validating AES CMAC PRF Params: %v", err)
	}
	if err := subtle.ValidateAESCMACPRFParams(2); err == nil {
		t.Errorf("Unexpected validation of too short key for AES CMAC PRF Params")
	}
}

func TestKeyLength(t *testing.T) {
	if _, err := subtle.NewAESCMACPRF([]byte{0x01, 0x02}); err == nil {
		t.Errorf("Expected NewAESCMACPRF to fail on short key")
	}
	if _, err := subtle.NewAESCMACPRF([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}); err != nil {
		t.Errorf("Expected NewAESCMACPRF to work on 16 byte key")
	}
	if _, err := subtle.NewAESCMACPRF([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}); err != nil {
		t.Errorf("Expected NewAESCMACPRF to work on 32 byte key")
	}
}

func TestAESCMACPRFOutputLength(t *testing.T) {
	prf, err := subtle.NewAESCMACPRF([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
	if err != nil {
		t.Errorf("Expected NewAESCMACPRF to work on 32 byte key")
	}
	for i := 0; i <= 16; i++ {
		output, err := prf.ComputePRF([]byte{0x01, 0x02}, uint32(i))
		if err != nil {
			t.Errorf("Expected to be able to compute AES CMAC PRF with %d output length", i)
		}
		if len(output) != i {
			t.Errorf("Expected AES CMAC PRF to compute %d bytes, got %d", i, len(output))
		}
	}
	for i := 17; i < 32; i++ {
		_, err := prf.ComputePRF([]byte{0x01, 0x02}, uint32(i))
		if err == nil {
			t.Errorf("Expected to not be able to compute AES CMAC PRF with %d output length", i)
		}
	}
}
