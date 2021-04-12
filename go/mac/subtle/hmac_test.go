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
	"strings"
	"testing"

	"github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/subtle/random"
)

var key, _ = hex.DecodeString("000102030405060708090a0b0c0d0e0f")
var data = []byte("Hello")
var hmacTests = []struct {
	hashAlg     string
	tagSize     uint32
	key         []byte
	data        []byte
	expectedMac string
}{
	{
		hashAlg:     "SHA256",
		tagSize:     32,
		data:        data,
		key:         key,
		expectedMac: "e0ff02553d9a619661026c7aa1ddf59b7b44eac06a9908ff9e19961d481935d4",
	},
	{
		hashAlg: "SHA512",
		tagSize: 64,
		data:    data,
		key:     key,
		expectedMac: "481e10d823ba64c15b94537a3de3f253c16642451ac45124dd4dde120bf1e5c15" +
			"e55487d55ba72b43039f235226e7954cd5854b30abc4b5b53171a4177047c9b",
	},
	// empty data
	{
		hashAlg:     "SHA256",
		tagSize:     32,
		data:        []byte{},
		key:         key,
		expectedMac: "07eff8b326b7798c9ccfcbdbe579489ac785a7995a04618b1a2813c26744777d",
	},
}

func TestHMACBasic(t *testing.T) {
	for i, test := range hmacTests {
		cipher, err := subtle.NewHMAC(test.hashAlg, test.key, test.tagSize)
		if err != nil {
			t.Errorf("cannot create new mac in test case %d: %s", i, err)
		}
		mac, err := cipher.ComputeMAC(test.data)
		if err != nil {
			t.Errorf("mac computation failed in test case %d: %s", i, err)
		}
		if hex.EncodeToString(mac) != test.expectedMac[:(test.tagSize*2)] {
			t.Errorf("incorrect mac in test case %d: expect %s, got %s",
				i, test.expectedMac[:(test.tagSize*2)], hex.EncodeToString(mac))
		}
		if err := cipher.VerifyMAC(mac, test.data); err != nil {
			t.Errorf("mac verification failed in test case %d: %s", i, err)
		}
	}
}

func TestNewHMACWithInvalidInput(t *testing.T) {
	// invalid hash algorithm
	_, err := subtle.NewHMAC("MD5", random.GetRandomBytes(16), 32)
	if err == nil || !strings.Contains(err.Error(), "invalid hash algorithm") {
		t.Errorf("expect an error when hash algorithm is invalid")
	}
	// key too short
	_, err = subtle.NewHMAC("SHA256", random.GetRandomBytes(1), 32)
	if err == nil || !strings.Contains(err.Error(), "key too short") {
		t.Errorf("expect an error when key is too short")
	}
	// tag too short
	_, err = subtle.NewHMAC("SHA256", random.GetRandomBytes(16), 9)
	if err == nil || !strings.Contains(err.Error(), "tag size too small") {
		t.Errorf("expect an error when tag size is too small")
	}
	// tag too big
	_, err = subtle.NewHMAC("SHA1", random.GetRandomBytes(16), 21)
	if err == nil || !strings.Contains(err.Error(), "tag size too big") {
		t.Errorf("expect an error when tag size is too big")
	}
	_, err = subtle.NewHMAC("SHA256", random.GetRandomBytes(16), 33)
	if err == nil || !strings.Contains(err.Error(), "tag size too big") {
		t.Errorf("expect an error when tag size is too big")
	}
	_, err = subtle.NewHMAC("SHA512", random.GetRandomBytes(16), 65)
	if err == nil || !strings.Contains(err.Error(), "tag size too big") {
		t.Errorf("expect an error when tag size is too big")
	}
}

func TestHMAComputeVerifyWithNilInput(t *testing.T) {
	cipher, err := subtle.NewHMAC("SHA256", random.GetRandomBytes(16), 32)
	if err != nil {
		t.Errorf("unexpected error when creating new HMAC")
	}
	tag, err := cipher.ComputeMAC(nil)
	if err != nil {
		t.Errorf("cipher.ComputeMAC(nil) failed: %v", err)
	}
	if err := cipher.VerifyMAC(tag, nil); err != nil {
		t.Errorf("cipher.VerifyMAC(tag, nil) failed: %v", err)
	}
}

func TestVerifyMACWithInvalidInput(t *testing.T) {
	cipher, err := subtle.NewHMAC("SHA256", random.GetRandomBytes(16), 32)
	if err != nil {
		t.Errorf("unexpected error when creating new HMAC")
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

func TestHMACModification(t *testing.T) {
	for i, test := range hmacTests {
		cipher, err := subtle.NewHMAC(test.hashAlg, test.key, test.tagSize)
		if err != nil {
			t.Errorf("cannot create new mac in test case %d: %s", i, err)
		}
		mac, _ := cipher.ComputeMAC(test.data)
		for i := 0; i < len(mac); i++ {
			tmp := mac[i]
			for j := 0; j < 8; j++ {
				mac[i] ^= 1 << uint8(j)
				err := cipher.VerifyMAC(mac, test.data)
				if err == nil {
					t.Errorf("test case %d: modified MAC should be invalid", i)
				}
				mac[i] = tmp
			}
		}
	}
}

func TestHMACTruncation(t *testing.T) {
	for i, test := range hmacTests {
		cipher, err := subtle.NewHMAC(test.hashAlg, test.key, test.tagSize)
		if err != nil {
			t.Errorf("cannot create new mac in test case %d: %s", i, err)
		}
		mac, _ := cipher.ComputeMAC(test.data)
		for i := 1; i < len(mac); i++ {
			tmp := mac[:i]
			err := cipher.VerifyMAC(tmp, test.data)
			if err == nil {
				t.Errorf("test case %d: truncated MAC should be invalid", i)
			}
		}
	}
}
