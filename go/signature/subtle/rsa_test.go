// Copyright 2021 Google LLC
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
	"math/big"
	"testing"

	"github.com/google/tink/go/signature/subtle"
)

func TestGenerateRSAKey(t *testing.T) {
	modulusSize := 2048
	publicExponent := 65537
	if _, err := subtle.GenerateRSAKey(modulusSize, publicExponent); err != nil {
		t.Fatalf("GenerateRSAKey() failed: %v", err)
	}
}

func TestGenerateRSAKeyInvalid(t *testing.T) {
	testCases := []struct {
		name           string
		modulusSize    int
		publicExponent int
	}{
		{
			name:           "InvalidModulusSize",
			modulusSize:    1024,
			publicExponent: 65537,
		},
		{
			name:           "InvalidPublicExponent",
			modulusSize:    2048,
			publicExponent: 3,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := subtle.GenerateRSAKey(tc.modulusSize, tc.publicExponent); err == nil {
				t.Fatal("GenerateRSAKey() succeeded with invalid input, want error")
			}
		})
	}
}

func TestRSAPublicKeyDataValidateCreateKey(t *testing.T) {
	keyData, err := createRSAPrivateKeyData()
	if err != nil {
		t.Fatalf("Failed creating RSA private key data: %v", err)
	}
	if err := keyData.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	if _, err := keyData.CreateKey(); err != nil {
		t.Fatalf("CreateKey() failed: %v", err)
	}
}

func TestRSAPublicKeyDataValidateCreateKeyInvalid(t *testing.T) {
	validKeyData, err := createRSAPrivateKeyData()
	if err != nil {
		t.Fatalf("Failed creating RSA private key data: %v", err)
	}
	testCases := []struct {
		name    string
		keyData *subtle.RSAPublicKeyData
	}{
		{
			name: "InvalidPublicExponent",
			keyData: &subtle.RSAPublicKeyData{
				E: 3,
				N: validKeyData.PublicKeyData.N,
			},
		},
		{
			name: "InvalidModulus",
			keyData: &subtle.RSAPublicKeyData{
				E: validKeyData.PublicKeyData.E,
				N: new(big.Int),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.keyData.Validate(); err == nil {
				t.Fatalf("Validate() succeeded with an invalid input, want error")
			}
			if _, err := tc.keyData.CreateKey(); err == nil {
				t.Fatalf("CreateKey() succeeded with an invalid input, want error")
			}
		})
	}
}

func TestRSAPrivateKeyDataValidateCreateKey(t *testing.T) {
	keyData, err := createRSAPrivateKeyData()
	if err != nil {
		t.Fatalf("Failed creating RSA private key data: %v", err)
	}
	if err := keyData.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	if _, err := keyData.CreateKey(); err != nil {
		t.Fatalf("CreateKey() failed: %v", err)
	}
}

func TestRSAPrivateKeyDataValidateCreateKeyInvalid(t *testing.T) {
	validKeyData, err := createRSAPrivateKeyData()
	if err != nil {
		t.Fatalf("Failed creating RSA private key data: %v", err)
	}
	testCases := []struct {
		name    string
		keyData *subtle.RSAPrivateKeyData
	}{
		{
			name: "InvalidPublicExponent",
			keyData: &subtle.RSAPrivateKeyData{
				D:    validKeyData.D,
				P:    validKeyData.P,
				Q:    validKeyData.Q,
				Dp:   validKeyData.Dp,
				Dq:   validKeyData.Dq,
				Qinv: validKeyData.Qinv,
				PublicKeyData: &subtle.RSAPublicKeyData{
					E: 3,
					N: validKeyData.PublicKeyData.N,
				},
			},
		},
		{
			name: "InvalidModulus",
			keyData: &subtle.RSAPrivateKeyData{
				D:    validKeyData.D,
				P:    validKeyData.P,
				Q:    validKeyData.Q,
				Dp:   validKeyData.Dp,
				Dq:   validKeyData.Dq,
				Qinv: validKeyData.Qinv,
				PublicKeyData: &subtle.RSAPublicKeyData{
					E: validKeyData.PublicKeyData.E,
					N: new(big.Int),
				},
			},
		},
		{
			name:    "ZeroValue",
			keyData: &subtle.RSAPrivateKeyData{},
		},
		{
			name: "InvalidValue",
			keyData: &subtle.RSAPrivateKeyData{
				D:    big.NewInt(2),
				P:    validKeyData.P,
				Q:    validKeyData.Q,
				Dp:   validKeyData.Dp,
				Dq:   validKeyData.Dq,
				Qinv: validKeyData.Qinv,
				PublicKeyData: &subtle.RSAPublicKeyData{
					E: validKeyData.PublicKeyData.E,
					N: validKeyData.PublicKeyData.N,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.keyData.Validate(); err == nil {
				t.Fatalf("Validate() succeeded with an invalid input, want error")
			}
			if _, err := tc.keyData.CreateKey(); err == nil {
				t.Fatalf("CreateKey() succeeded with an invalid input, want error")
			}
		})
	}
}

func createRSAPrivateKeyData() (*subtle.RSAPrivateKeyData, error) {
	privKey, err := subtle.GenerateRSAKey(2048, 65537)
	if err != nil {
		return nil, err
	}
	return &subtle.RSAPrivateKeyData{
		D:    privKey.D,
		P:    privKey.Primes[0],
		Q:    privKey.Primes[1],
		Dp:   privKey.Precomputed.Dp,
		Dq:   privKey.Precomputed.Dq,
		Qinv: privKey.Precomputed.Qinv,
		PublicKeyData: &subtle.RSAPublicKeyData{
			E: privKey.PublicKey.E,
			N: privKey.PublicKey.N,
		},
	}, nil
}
