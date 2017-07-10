// Copyright 2017 Google Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
////////////////////////////////////////////////////////////////////////////////
package hmac_test

import (
  "fmt"
  "testing"
  "crypto/sha256"
  "crypto/sha512"
  "encoding/hex"
  "github.com/google/tink/go/tink/tink"
  "github.com/google/tink/go/subtle/hmac"
)

type HmacTest struct {
  h hmac.Hmac
  data []byte
  expectedMac string
}

var key, _ = hex.DecodeString("000102030405060708090a0b0c0d0e0f")
var data = []byte("Hello")

var hmacTests = []HmacTest{
  HmacTest{
    h: hmac.Hmac{HashFunc: sha256.New, Key: key, TagSize: 32},
    data: data,
    expectedMac: "e0ff02553d9a619661026c7aa1ddf59b7b44eac06a9908ff9e19961d481935d4",
  },
  HmacTest{
    h: hmac.Hmac{HashFunc: sha512.New, Key: key, TagSize: 64},
    data: data,
    expectedMac: "481e10d823ba64c15b94537a3de3f253c16642451ac45124dd4dde120bf1e5c15" +
        "e55487d55ba72b43039f235226e7954cd5854b30abc4b5b53171a4177047c9b",
  },
  // empty data
  HmacTest{
    h: hmac.Hmac{HashFunc: sha256.New, Key: key, TagSize: 32},
    data: []byte{},
    expectedMac: "07eff8b326b7798c9ccfcbdbe579489ac785a7995a04618b1a2813c26744777d",
  },
}

func TestBasic(t *testing.T) {
  for _, test := range hmacTests {
    mac, err := test.h.ComputeMac(test.data)
    if hex.EncodeToString(mac) != test.expectedMac[:(test.h.TagSize*2)] {
      t.Errorf("incorrect mac computation")
    }
    if err != nil {
      t.Errorf("failed to compute mac")
    }
    valid, err := test.h.VerifyMac(mac, test.data)
    if !valid || err != nil {
      t.Errorf("failed to verify mac")
    }
  }
}

func TestInvalidInput(t *testing.T) {
  var test HmacTest = hmacTests[0]
  if m, err := test.h.ComputeMac(nil); err == nil {
    fmt.Println(hex.EncodeToString(m))
    t.Errorf("ComputerMac(): expect an error when input is nil")
  }
  if _, err := test.h.VerifyMac(nil, []byte{1}); err == nil {
    t.Errorf("VerifyMac(): expect an error when mac is nil")
  }
  if _, err := test.h.VerifyMac([]byte{1}, nil); err == nil {
    t.Errorf("VerifyMac(): expect an error when data is nil")
  }
}

func TestModification(t *testing.T) {
  for _, test := range hmacTests {
    mac, _ := test.h.ComputeMac(test.data)
    for i := 0; i < len(mac); i++ {
      tmp := mac[i]
      for j := 0; j < 8; j++ {
        mac[i] ^= 1 << uint8(j)
        valid, _ := test.h.VerifyMac(mac, test.data)
        if valid {
          t.Errorf("modified MAC should be invalid")
        }
        mac[i] = tmp
      }
    }
  }
}

func TestTruncation(t *testing.T) {
  for _, test := range hmacTests {
    mac, _ := test.h.ComputeMac(test.data)
    for i := 1; i < len(mac); i++ {
      tmp := mac[:i]
      valid, _ := test.h.VerifyMac(tmp, test.data)
      if valid {
        t.Errorf("truncated MAC should be invalid")
      }
    }
  }
}

func TestTooBigTagSize(t *testing.T) {
  test := hmacTests[0]
  test.h.TagSize = 33
  _, err := test.h.ComputeMac(test.data)
  if err == nil {
    t.Errorf("expect an error when digest size is too big")
  }
}

func testMacInterface(t *testing.T) {
  // This line throws an error if Hmac doesn't implement Mac interface
  var _ tink.Mac = (*hmac.Hmac)(nil)
}