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
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/subtle/random"
)

var (
	// Test vectors from RFC 4493.
	keyRFC4493, _  = hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	dataRFC4493, _ = hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	expected       = map[int]string{
		0:  "bb1d6929e95937287fa37d129b756746",
		16: "070a16b46b4d4144f79bdd9dd04a287c",
		40: "dfa66747de9ae63030ca32611497c827",
		64: "51f0bebf7e3b9d92fc49741779363cfe",
	}
)

type testdata struct {
	Algorithm        string
	GeneratorVersion string
	NumberOfTests    uint32
	TestGroups       []*testgroup
}

type testgroup struct {
	KeySize uint32
	TagSize uint32
	Type    string
	Tests   []*testcase
}

type testcase struct {
	Comment string
	Key     string
	Msg     string
	Result  string
	Tag     string
	TcID    uint32
}

func TestVectorsWycheproof(t *testing.T) {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}
	f, err := os.Open(filepath.Join(srcDir, "wycheproof/testvectors/aes_cmac_test.json"))
	if err != nil {
		t.Fatalf("cannot open file: %s", err)
	}
	parser := json.NewDecoder(f)
	data := new(testdata)
	if err := parser.Decode(data); err != nil {
		t.Fatalf("cannot decode test data: %s", err)
	}

	for _, g := range data.TestGroups {
		for _, tc := range g.Tests {
			key, err := hex.DecodeString(tc.Key)
			if err != nil || uint32(len(key))*8 != g.KeySize {
				t.Errorf("Could not decode key for test case %d (%s): %v", tc.TcID, tc.Comment, err)
				continue
			}
			msg, err := hex.DecodeString(tc.Msg)
			if err != nil {
				t.Errorf("Could not decode message for test case %d (%s): %v", tc.TcID, tc.Comment, err)
				continue
			}
			tag, err := hex.DecodeString(tc.Tag)
			if err != nil {
				t.Errorf("Could not decode expected tag for test case %d (%s): %v", tc.TcID, tc.Comment, err)
				continue
			}
			if g.TagSize%8 != 0 {
				t.Errorf("Requested tag size for test case %d (%s) is not a multiple of 8, but %d", tc.TcID, tc.Comment, g.TagSize)
				continue
			}
			aes, err := subtle.NewAESCMAC(key, g.TagSize/8)
			valid := tc.Result == "valid"
			if valid && err != nil {
				t.Errorf("Could not create subtle.CMAC for test case %d (%s): %v", tc.TcID, tc.Comment, err)
				continue
			}
			if !valid && err != nil {
				continue
			}
			res, err := aes.ComputeMAC(msg)
			if valid && err != nil {
				t.Errorf("Could not compute AES-CMAC for test case %d (%s): %v", tc.TcID, tc.Comment, err)
				continue
			}
			if valid && hex.EncodeToString(res) != tc.Tag {
				t.Errorf("Compute AES-CMAC and expected for test case %d (%s) do not match:\nComputed: %q\nExpected: %q", tc.TcID, tc.Comment, hex.EncodeToString(res), tc.Tag)
			}
			if !valid && hex.EncodeToString(res) == tc.Tag && err == nil {
				t.Errorf("Compute AES-CMAC and invalid expected for test case %d (%s) match:\nComputed: %q\nExpected: %q", tc.TcID, tc.Comment, hex.EncodeToString(res), tc.Tag)
			}
			err = aes.VerifyMAC(tag, msg)
			if valid && err != nil {
				t.Errorf("Could not verify MAC for test case %d (%s): %v", tc.TcID, tc.Comment, err)
			}
			if !valid && err == nil {
				t.Errorf("Verified invalid MAC for test case %d (%s)", tc.TcID, tc.Comment)
			}
		}
	}
}

func TestCMACBasic(t *testing.T) {
	a, err := subtle.NewAESCMAC(keyRFC4493, 16)
	if err != nil {
		t.Errorf("Could not create subtle.CMAC object: %v", err)
	}
	for l, e := range expected {
		output, err := a.ComputeMAC(dataRFC4493[:l])
		if err != nil {
			t.Errorf("Error computing AES-CMAC: %v", err)
		}
		if hex.EncodeToString(output) != e {
			t.Errorf("Computation and test vector differ. Computation: %q, Test Vector %q", hex.EncodeToString(output), e)
		}
		exp, err := hex.DecodeString(e)
		if err != nil {
			t.Errorf("Could not decode expected string %q: %v", e, err)
		}
		err = a.VerifyMAC(exp, dataRFC4493[:l])
		if err != nil {
			t.Errorf("Verification of test vector failed. Test Vector %q, Verification %v", e, err)
		}
	}
}

func TestNewCMACWithInvalidInput(t *testing.T) {
	// key too short
	_, err := subtle.NewAESCMAC(random.GetRandomBytes(1), 16)
	if err == nil {
		t.Errorf("expect an error when key is too short")
	}
	// tag too short
	_, err = subtle.NewAESCMAC(random.GetRandomBytes(16), 9)
	if err == nil {
		t.Errorf("expect an error when tag size is too small")
	}
	// tag too big
	_, err = subtle.NewAESCMAC(random.GetRandomBytes(16), 17)
	if err == nil {
		t.Errorf("expect an error when tag size is too big")
	}
}

func TestCMACComputeVerifyWithNilInput(t *testing.T) {
	cipher, err := subtle.NewAESCMAC(random.GetRandomBytes(16), 16)
	if err != nil {
		t.Errorf("unexpected error when creating new CMAC")
	}
	tag, err := cipher.ComputeMAC(nil)
	if err != nil {
		t.Errorf("cipher.ComputeMAC(nil) failed: %v", err)
	}
	if err := cipher.VerifyMAC(tag, nil); err != nil {
		t.Errorf("cipher.VerifyMAC(tag, nil) failed: %v", err)
	}
}

func TestCMACVerifyMACWithInvalidInput(t *testing.T) {
	cipher, err := subtle.NewAESCMAC(random.GetRandomBytes(16), 16)
	if err != nil {
		t.Errorf("unexpected error when creating new CMAC")
	}
	if err := cipher.VerifyMAC(nil, []byte{1}); err == nil {
		t.Errorf("expect an error when mac is nil")
	}
	if err := cipher.VerifyMAC([]byte{1}, nil); err == nil {
		t.Errorf("expect an error when data is nil")
	}
	if err := cipher.VerifyMAC(nil, nil); err == nil {
		t.Errorf("cipher.VerifyMAC(nil, nil) succeeded unexpectedly")
	}
}

func TestCMACModification(t *testing.T) {
	a, err := subtle.NewAESCMAC(keyRFC4493, 16)
	if err != nil {
		t.Errorf("Could not create subtle.CMAC object: %v", err)
	}
	for l, e := range expected {
		exp, err := hex.DecodeString(e)
		if err != nil {
			t.Errorf("Could not decode expected string %q: %v", e, err)
		}
		for i := 0; i < len(exp); i++ {
			for j := 0; j < 8; j++ {
				notExpected := make([]byte, 16)
				copy(notExpected, exp)
				notExpected[i] ^= 1 << uint8(j)
				err = a.VerifyMAC(notExpected, dataRFC4493[:l])
				if err == nil {
					t.Errorf("Verification of modified test vector did not fail. Test Vector %q, Modified: %q", e, hex.EncodeToString(notExpected))
				}
			}
		}
	}
}

func TestCMACTruncation(t *testing.T) {
	a, err := subtle.NewAESCMAC(keyRFC4493, 16)
	if err != nil {
		t.Errorf("Could not create subtle.CMAC object: %v", err)
	}
	for l, e := range expected {
		exp, err := hex.DecodeString(e)
		if err != nil {
			t.Errorf("Could not decode expected string %q: %v", e, err)
		}
		for i := 1; i < len(exp); i++ {
			notExpected := exp[:i]
			err = a.VerifyMAC(notExpected, dataRFC4493[:l])
			if err == nil {
				t.Errorf("Verification of truncated test vector did not fail. Test Vector %q, Modified: %q", e, hex.EncodeToString(notExpected))
			}
		}
	}
}

func TestCMACSmallerTagSize(t *testing.T) {
	for i := 10; i <= 16; i++ {
		a, err := subtle.NewAESCMAC(keyRFC4493, uint32(i))
		if err != nil {
			t.Errorf("Could not create subtle.CMAC object: %v", err)
		}
		for l, e := range expected {
			exp, err := hex.DecodeString(e)
			if err != nil {
				t.Errorf("Could not decode expected string %q: %v", e, err)
			}
			err = a.VerifyMAC(exp[:i], dataRFC4493[:l])
			if err != nil {
				t.Errorf("Verification of smaller tag test vector did fail. Test Vector %q, Verification: %v", hex.EncodeToString(exp[:i]), err)
			}
		}
	}
}
