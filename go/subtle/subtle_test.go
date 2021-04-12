// Copyright 2019 Google LLC
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
	"hash"
	"testing"

	"github.com/google/tink/go/subtle"
)

func TestConvertHashName(t *testing.T) {
	if subtle.ConvertHashName("SHA-256") != "SHA256" ||
		subtle.ConvertHashName("SHA-1") != "SHA1" ||
		subtle.ConvertHashName("SHA-512") != "SHA512" ||
		subtle.ConvertHashName("UNKNOWN_HASH") != "" {
		t.Errorf("incorrect hash name conversion")
	}
}

func TestConvertCurveName(t *testing.T) {
	if subtle.ConvertCurveName("secp256r1") != "NIST_P256" ||
		subtle.ConvertCurveName("secp384r1") != "NIST_P384" ||
		subtle.ConvertCurveName("secp521r1") != "NIST_P521" ||
		subtle.ConvertCurveName("UNKNOWN_CURVE") != "" {
		t.Errorf("incorrect curve name conversion")
	}
}

func TestComputeHash(t *testing.T) {
	data := []byte("Hello")
	var tests = []struct {
		hashFunc     func() hash.Hash
		expectedHash string
	}{
		{subtle.GetHashFunc("SHA1"), "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0"},
		{subtle.GetHashFunc("SHA256"), "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"},
		{subtle.GetHashFunc("SHA512"), "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315"},
	}

	for _, tt := range tests {
		hashFunc := tt.hashFunc
		if hashFunc == nil {
			t.Fatal("got nil hash func")
		}
		hashed, err := subtle.ComputeHash(hashFunc, data)
		if err != nil {
			t.Fatalf("got error: %q", err)
		}
		if gotHash := hex.EncodeToString(hashed); gotHash != tt.expectedHash {
			t.Fatalf("Expected: %s. Got: %s", tt.expectedHash, gotHash)
		}
	}

	// unknown
	if subtle.GetHashFunc("UNKNOWN_HASH") != nil {
		t.Errorf("unexpected result for invalid hash types")
	}
}

func TestGetCurve(t *testing.T) {
	if subtle.GetCurve("NIST_P256").Params().Name != "P-256" {
		t.Errorf("incorrect result for NIST_P256")
	}
	if subtle.GetCurve("NIST_P384").Params().Name != "P-384" {
		t.Errorf("incorrect result for NIST_P384")
	}
	if subtle.GetCurve("NIST_P521").Params().Name != "P-521" {
		t.Errorf("incorrect result for NIST_P521")
	}
	if subtle.GetCurve("UNKNOWN_CURVE") != nil {
		t.Errorf("expect nil when curve is unknown")
	}
}
