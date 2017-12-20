// Copyright 2017 Google Inc.
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
package subtleutil_test

import (
  "encoding/hex"
  "testing"
  "github.com/google/tink/go/subtle/subtleutil"
)

func TestConvertHashName(t *testing.T) {
  if subtleutil.ConvertHashName("SHA-256") != "SHA256" ||
    subtleutil.ConvertHashName("SHA-1") != "SHA1" ||
    subtleutil.ConvertHashName("SHA-512") != "SHA512" ||
    subtleutil.ConvertHashName("UNKNOWN_HASH") != "" {
    t.Errorf("incorrect hash name conversion")
  }
}

func TestConvertCurveName(t *testing.T) {
  if subtleutil.ConvertCurveName("secp256r1") != "NIST_P256" ||
    subtleutil.ConvertCurveName("secp384r1") != "NIST_P384" ||
    subtleutil.ConvertCurveName("secp521r1") != "NIST_P521" ||
    subtleutil.ConvertCurveName("UNKNOWN_CURVE") != "" {
    t.Errorf("incorrect curve name conversion")
  }
}


func TestComputeHash(t *testing.T) {
  data := []byte("Hello")
  // SHA1
  expectedMac := "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0"
  hashFunc := subtleutil.GetHashFunc("SHA1")
  if hashFunc == nil || hex.EncodeToString(subtleutil.ComputeHash(hashFunc, data)) != expectedMac {
    t.Errorf("invalid hash function for SHA1")
  }
  // SHA256
  expectedMac = "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"
  hashFunc = subtleutil.GetHashFunc("SHA256")
  if hashFunc == nil || hex.EncodeToString(subtleutil.ComputeHash(hashFunc, data)) != expectedMac {
    t.Errorf("invalid hash function for SHA256")
  }
  // SHA512
  expectedMac = "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf" +
                "777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315"
  hashFunc = subtleutil.GetHashFunc("SHA512")
  if hashFunc == nil || hex.EncodeToString(subtleutil.ComputeHash(hashFunc, data)) != expectedMac {
    t.Errorf("invalid hash function for SHA512")
  }
  // unknown
  if subtleutil.GetHashFunc("UNKNOWN_HASH") != nil {
    t.Errorf("unexpected result for invalid hash types")
  }
}

func TestGetCurve(t *testing.T) {
  if subtleutil.GetCurve("NIST_P224").Params().Name != "P-224" {
    t.Errorf("incorrect result for NIST_P224")
  }
  if subtleutil.GetCurve("NIST_P256").Params().Name != "P-256" {
    t.Errorf("incorrect result for NIST_P256")
  }
  if subtleutil.GetCurve("NIST_P384").Params().Name != "P-384" {
    t.Errorf("incorrect result for NIST_P384")
  }
  if subtleutil.GetCurve("NIST_P521").Params().Name != "P-521" {
    t.Errorf("incorrect result for NIST_P521")
  }
  if subtleutil.GetCurve("UNKNOWN_CURVE") != nil {
    t.Errorf("expect nil when curve is unknown")
  }
}