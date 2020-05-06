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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type rfc5869test struct {
	hash        string
	key         string
	salt        string
	info        string
	ouputLength uint32
	okm         string
}

func TestVectorsRFC5869(t *testing.T) {
	// Test vectors from RFC 5869.
	testvectors := []*rfc5869test{
		&rfc5869test{
			hash:        "SHA256",
			key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "000102030405060708090a0b0c",
			info:        "f0f1f2f3f4f5f6f7f8f9",
			ouputLength: 42,
			okm:         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		&rfc5869test{
			hash:        "SHA256",
			key:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt:        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info:        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			ouputLength: 82,
			okm:         "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		&rfc5869test{
			hash:        "SHA256",
			key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "",
			info:        "",
			ouputLength: 42,
			okm:         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
		&rfc5869test{
			hash:        "SHA1",
			key:         "0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "000102030405060708090a0b0c",
			info:        "f0f1f2f3f4f5f6f7f8f9",
			ouputLength: 42,
			okm:         "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
		},
		&rfc5869test{
			hash:        "SHA1",
			key:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt:        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info:        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			ouputLength: 82,
			okm:         "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
		},
		&rfc5869test{
			hash:        "SHA1",
			key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "",
			info:        "",
			ouputLength: 42,
			okm:         "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
		},
		&rfc5869test{
			hash:        "SHA1",
			key:         "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
			salt:        "",
			info:        "",
			ouputLength: 42,
			okm:         "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
		},
	}
	for _, v := range testvectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Errorf("Could not decode key: %v", err)
		}
		salt, err := hex.DecodeString(v.salt)
		if err != nil {
			t.Errorf("Could not decode salt: %v", err)
		}
		info, err := hex.DecodeString(v.info)
		if err != nil {
			t.Errorf("Could not decode info: %v", err)
		}
		p, err := NewHKDFPRF(v.hash, key, salt)
		if err != nil {
			t.Errorf("Could not create HKDF object: %v", err)
		}
		output, err := p.ComputePRF(info, v.ouputLength)
		if err != nil {
			t.Errorf("Error computing HKDF: %v", err)
		}
		if hex.EncodeToString(output) != v.okm {
			t.Errorf("Computation and test vector differ. Computation: %q, Test Vector %q", hex.EncodeToString(output), v.okm)
		}
	}
}

type hkdftestdata struct {
	Algorithm        string
	GeneratorVersion string
	NumberOfTests    uint32
	TestGroups       []*hkdftestgroup
}

type hkdftestgroup struct {
	KeySize uint32
	Type    string
	Tests   []*hkdftestcase
}

type hkdftestcase struct {
	TcID    uint32
	Comment string
	IKM     string
	Salt    string
	Info    string
	Size    uint32
	OKM     string
	Result  string
}

func TestVectorsHKDFWycheproof(t *testing.T) {
	for _, hash := range []string{"SHA1", "SHA256", "SHA512"} {
		f, err := os.Open(fmt.Sprintf(os.Getenv("TEST_SRCDIR") + "/wycheproof/testvectors/hkdf_%s_test.json", strings.ToLower(hash)))
		if err != nil {
			t.Fatalf("cannot open file: %s, make sure that github.com/google/wycheproof is in your gopath", err)
		}
		parser := json.NewDecoder(f)
		data := new(hkdftestdata)
		if err := parser.Decode(data); err != nil {
			t.Fatalf("cannot decode test data: %s", err)
		}

		for _, g := range data.TestGroups {
			for _, tc := range g.Tests {
				ikm, err := hex.DecodeString(tc.IKM)
				if err != nil || uint32(len(ikm))*8 != g.KeySize {
					t.Errorf("Could not decode key for test case %d (%s): %v", tc.TcID, tc.Comment, err)
					continue
				}
				salt, err := hex.DecodeString(tc.Salt)
				if err != nil {
					t.Errorf("Could not decode salt for test case %d (%s): %v", tc.TcID, tc.Comment, err)
					continue
				}
				info, err := hex.DecodeString(tc.Info)
				if err != nil {
					t.Errorf("Could not decode salt for test case %d (%s): %v", tc.TcID, tc.Comment, err)
					continue
				}
				hkdfPRF, err := NewHKDFPRF(hash, ikm, salt)
				valid := tc.Result == "valid"
				if valid && err != nil {
					t.Errorf("Could not create HKDF %s PRF for test case %d (%s): %v", hash, tc.TcID, tc.Comment, err)
					continue
				}
				if !valid && err != nil {
					continue
				}
				res, err := hkdfPRF.ComputePRF(info, tc.Size)
				if valid && err != nil {
					t.Errorf("Could not compute HKDF %s PRF for test case %d (%s): %v", hash, tc.TcID, tc.Comment, err)
					continue
				}
				if !valid && err != nil {
					continue
				}
				if valid && hex.EncodeToString(res) != tc.OKM {
					t.Errorf("Compute HKDF %s PRF and expected for test case %d (%s) do not match:\nComputed: %q\nExpected: %q", hash, tc.TcID, tc.Comment, hex.EncodeToString(res), tc.OKM)
				}
				if !valid && hex.EncodeToString(res) == tc.OKM {
					t.Errorf("Compute HKDF %s PRF and invalid expected for test case %d (%s) match:\nComputed: %q\nExpected: %q", hash, tc.TcID, tc.Comment, hex.EncodeToString(res), tc.OKM)
				}
			}
		}
	}
}

func TestHKDFPRFHash(t *testing.T) {
	if _, err := NewHKDFPRF("SHA256", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, []byte{}); err != nil {
		t.Errorf("Expected NewHKDFPRF to work with SHA256: %v", err)
	}
	if _, err := NewHKDFPRF("SHA512", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, []byte{}); err != nil {
		t.Errorf("Expected NewHKDFPRF to work with SHA512: %v", err)
	}
	if _, err := NewHKDFPRF("SHA1", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, []byte{}); err != nil {
		t.Errorf("Expected NewHKDFPRF to work with SHA1: %v", err)
	}
	if _, err := NewHKDFPRF("md5", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, []byte{}); err == nil {
		t.Errorf("Expected NewHKDFPRF to fail with md5")
	}
}

func TestHKDFPRFSalt(t *testing.T) {
	if _, err := NewHKDFPRF("SHA256", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, nil); err != nil {
		t.Errorf("Expected NewHKDFPRF to work nil salt: %v", err)
	}
	if _, err := NewHKDFPRF("SHA256", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, []byte{}); err != nil {
		t.Errorf("Expected NewHKDFPRF to work empty salt: %v", err)
	}
	if _, err := NewHKDFPRF("SHA256", []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, []byte{0xaf, 0xfe, 0xc0, 0xff, 0xee}); err != nil {
		t.Errorf("Expected NewHKDFPRF to work with salt: %v", err)
	}
}

func TestHKDFPRFOutputLength(t *testing.T) {
	for hash, length := range map[string]int{"SHA1": 20, "SHA256": 32, "SHA512": 64} {
		prf, err := NewHKDFPRF(hash, []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, []byte{})
		if err != nil {
			t.Errorf("Expected NewHKDFPRF to work on 32 byte key with hash %s", hash)
		}
		for i := 0; i <= length*255; i++ {
			output, err := prf.ComputePRF([]byte{0x01, 0x02}, uint32(i))
			if err != nil {
				t.Errorf("Expected to be able to compute HKDF %s PRF with %d output length", hash, i)
			}
			if len(output) != i {
				t.Errorf("Expected HKDF %s PRF to compute %d bytes, got %d", hash, i, len(output))
			}
		}
		for i := length*255 + 1; i < length*255+100; i++ {
			_, err := prf.ComputePRF([]byte{0x01, 0x02}, uint32(i))
			if err == nil {
				t.Errorf("Expected to not be able to compute HKDF %s PRF with %d output length", hash, i)
			}
		}
	}
}

func TestValidateHKDFPRFParams(t *testing.T) {
	if err := ValidateHKDFPRFParams("SHA256", 32, []byte{}); err != nil {
		t.Errorf("Unexpected error for valid HKDF PRF params: %v", err)
	}
	if err := ValidateHKDFPRFParams("SHA256", 32, nil); err != nil {
		t.Errorf("Unexpected error for valid HKDF PRF params: %v", err)
	}
	if err := ValidateHKDFPRFParams("SHA256", 32, []byte{0xaf, 0xfe, 0xc0, 0xff, 0xee}); err != nil {
		t.Errorf("Unexpected error for salted valid HKDF PRF params: %v", err)
	}
	if err := ValidateHKDFPRFParams("SHA256", 4, []byte{}); err == nil {
		t.Errorf("Short key size not detected for HKDF PRF params")
	}
	if err := ValidateHKDFPRFParams("md5", 32, []byte{}); err == nil {
		t.Errorf("Weak hash function not detected for HKDF PRF params")
	}
	if err := ValidateHKDFPRFParams("SHA1", 32, []byte{}); err == nil {
		t.Errorf("Weak hash function not detected for HKDF PRF params")
	}
}
