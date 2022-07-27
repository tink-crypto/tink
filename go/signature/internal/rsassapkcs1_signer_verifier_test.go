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

package internal_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/tink/go/signature/internal"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/testutil"
)

func TestRSASSAPKCS1SignVerify(t *testing.T) {
	data := random.GetRandomBytes(20)
	hash := "SHA256"
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, 2048) err = %v, want nil", err)
	}
	signer, err := internal.New_RSA_SSA_PKCS1_Signer(hash, privKey)
	if err != nil {
		t.Fatalf("New_RSA_SSA_PKCS1_Signer() err = %v, want nil", err)
	}
	verifier, err := internal.New_RSA_SSA_PKCS1_Verifier(hash, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("New_RSA_SSA_PKCS1_Verifier() err = %v, want nil", err)
	}
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() err = %v, want nil", err)
	}
	if err := verifier.Verify(signature, data); err != nil {
		t.Fatalf("Verify() err = %v, want nil", err)
	}
}

func TestRSASSAPKCS1ModifySignatureFails(t *testing.T) {
	data := random.GetRandomBytes(20)
	hash := "SHA256"
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, 2048) err = %v, want nil", err)
	}
	signer, err := internal.New_RSA_SSA_PKCS1_Signer(hash, privKey)
	if err != nil {
		t.Fatalf("New_RSA_SSA_PKCS1_Signer() err = %v, want nil", err)
	}
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() err = %v, want nil", err)
	}
	verifier, err := internal.New_RSA_SSA_PKCS1_Verifier(hash, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("New_RSA_SSA_PKCS1_Verifier() err = %v, want nil", err)
	}
	appendSig := append(signature, 0x01)
	if err := verifier.Verify(appendSig, data); err == nil {
		t.Fatalf("Verify() err = nil, want error")
	}
	truncSig := signature[:len(signature)-2]
	if err := verifier.Verify(truncSig, data); err == nil {
		t.Fatalf("Verify() err = nil, want error")
	}
	signature[0] <<= 1
	if err := verifier.Verify(truncSig, data); err == nil {
		t.Fatalf("Verify() err = nil, want error")
	}
}

func TestNewRSASSAPKCS1SignerVerifierInvalidInput(t *testing.T) {
	validPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, 2048) err = %v, want nil", err)
	}
	rsaShortModulusKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("decoding rsa short modulus: %v", err)
	}
	testCases := []struct {
		name    string
		hash    string
		privKey *rsa.PrivateKey
	}{
		{
			name:    "weak signature hash algorithm",
			hash:    "SHA1",
			privKey: validPrivKey,
		},
		{
			name: "invalid public key exponent",
			hash: "SHA256",
			privKey: &rsa.PrivateKey{
				D:           validPrivKey.D,
				Primes:      validPrivKey.Primes,
				Precomputed: validPrivKey.Precomputed,
				PublicKey: rsa.PublicKey{
					N: validPrivKey.PublicKey.N,
					E: 3,
				},
			},
		},
		{
			name:    "small modulus size",
			hash:    "SHA256",
			privKey: rsaShortModulusKey,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := internal.New_RSA_SSA_PKCS1_Signer(tc.hash, tc.privKey); err == nil {
				t.Errorf("New_RSA_SSA_PKCS1_Signer() err = nil, want error")
			}
			if _, err := internal.New_RSA_SSA_PKCS1_Verifier(tc.hash, &tc.privKey.PublicKey); err == nil {
				t.Errorf("New_RSA_SSA_PKCS1_Verifier() err = nil, want error")
			}
		})
	}
}

type rsaSSAPKCS1Suite struct {
	testutil.WycheproofSuite
	TestGroups []*rsaSSAPKCS1Group `json:"testGroups"`
}

type rsaSSAPKCS1Group struct {
	testutil.WycheproofGroup
	SHA   string             `json:"sha"`
	E     testutil.HexBytes  `json:"e"`
	N     testutil.HexBytes  `json:"n"`
	Type  string             `json:"type"`
	Tests []*rsaSSAPKCS1Case `json:"tests"`
}

type rsaSSAPKCS1Case struct {
	testutil.WycheproofCase
	Message   testutil.HexBytes `json:"msg"`
	Signature testutil.HexBytes `json:"sig"`
}

func TestRSASSAPKCS1WycheproofCases(t *testing.T) {
	testsRan := 0
	for _, v := range []string{
		"rsa_signature_2048_sha256_test.json",
		"rsa_signature_3072_sha512_test.json",
		"rsa_signature_4096_sha512_test.json",
	} {
		suite := &rsaSSAPKCS1Suite{}
		if err := testutil.PopulateSuite(suite, v); err != nil {
			t.Fatalf("testutil.PopulateSuite() err = %v, want nil", err)
		}
		for _, group := range suite.TestGroups {
			hash := subtle.ConvertHashName(group.SHA)
			if hash == "" {
				t.Fatalf("invalid hash name")
			}
			publicKey := &rsa.PublicKey{
				E: int(new(big.Int).SetBytes(group.E).Uint64()),
				N: new(big.Int).SetBytes(group.N),
			}
			if publicKey.E != 65537 {
				// golang "crypto/rsa" only supports 65537 as an exponent.
				if _, err := internal.New_RSA_SSA_PKCS1_Verifier(hash, publicKey); err == nil {
					t.Errorf("NewRSASSAPKCS1Verifier() err = nil, want error")
				}
				continue
			}
			verifier, err := internal.New_RSA_SSA_PKCS1_Verifier(hash, publicKey)
			if err != nil {
				t.Fatalf("NewRSASSAPKCS1Verifier() err = %v, want nil", err)
			}
			for _, test := range group.Tests {
				caseName := fmt.Sprintf("%s: %s-%s:Case-%d", v, group.Type, group.SHA, test.CaseID)
				t.Run(caseName, func(t *testing.T) {
					testsRan++
					err := verifier.Verify(test.Signature, test.Message)
					switch test.Result {
					case "valid":
						if err != nil {
							t.Errorf("Verify() err = %v, want nil", err)
						}
					case "invalid":
						if err == nil {
							t.Errorf("Verify() err = nil, want error")
						}
					case "acceptable":
						// TODO(b/230489047): Inspect flags to appropriately handle acceptable test cases.
					default:
						t.Errorf("unsupported test result: %q", test.Result)
					}
				})
			}
		}
	}
	if testsRan != 716 {
		t.Errorf("testsRan = %d, want = %d", testsRan, 716)
	}
}
