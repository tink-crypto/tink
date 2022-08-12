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

package signature_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/tink/go/internal/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/testutil"
)

func TestRSASSAPSSSignVerify(t *testing.T) {
	data := random.GetRandomBytes(20)
	sigHash := "SHA256"
	saltLength := 10
	privKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, 3072) err = %v, want nil", err)
	}
	signer, err := signature.New_RSA_SSA_PSS_Signer(sigHash, saltLength, privKey)
	if err != nil {
		t.Fatalf("New_RSA_SSA_PSS_Signer() error = %v, want nil", err)
	}
	verifier, err := signature.New_RSA_SSA_PSS_Verifier(sigHash, saltLength, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("New_RSA_SSA_PSS_Verifier() error = %v, want nil", err)
	}
	s, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() err = %v, want nil", err)
	}
	if err = verifier.Verify(s, data); err != nil {
		t.Fatalf("Verify() err = %v, want nil", err)
	}
}

func TestRSASSAPSSSignVerifyInvalidFails(t *testing.T) {
	data := random.GetRandomBytes(20)
	sigHash := "SHA256"
	saltLength := 10
	privKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, 3072) err = %v, want nil", err)
	}
	signer, err := signature.New_RSA_SSA_PSS_Signer(sigHash, saltLength, privKey)
	if err != nil {
		t.Fatalf("New_RSA_SSA_PSS_Signer() error = %v, want nil", err)
	}
	verifier, err := signature.New_RSA_SSA_PSS_Verifier(sigHash, saltLength, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("New_RSA_SSA_PSS_Verifier() error = %v, want nil", err)
	}
	s, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() err = %v, want nil", err)
	}
	if err = verifier.Verify(s, data); err != nil {
		t.Fatalf("Verify() err = %v, want nil", err)
	}

	modifiedSig := s[:]
	// modify first byte in signature
	modifiedSig[0] <<= 1
	if err := verifier.Verify(modifiedSig, data); err == nil {
		t.Errorf("Verify(modifiedSig, data) err = nil, want error")
	}
	if err := verifier.Verify(s, []byte("invalid_data")); err == nil {
		t.Errorf("Verify(s, invalid_data) err = nil, want error")
	}
	if err := verifier.Verify([]byte("invalid_signature"), data); err == nil {
		t.Errorf("Verify(invalid_signature, data) err = nil, want error")
	}

	diffPrivKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, 3072) err = %v, want nil", err)
	}
	diffVerifier, err := signature.New_RSA_SSA_PSS_Verifier(sigHash, saltLength, &diffPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("New_RSA_SSA_PSS_Verifier() error = %v, want nil", err)
	}
	if err := diffVerifier.Verify(s, data); err == nil {
		t.Errorf("Verify() err = nil, want error")
	}
}

func TestNewRSASSAPSSSignerVerifierFailWithInvalidInputs(t *testing.T) {
	type testCase struct {
		name    string
		hash    string
		salt    int
		privKey *rsa.PrivateKey
	}
	validPrivKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, 3072) err = %v, want nil", err)
	}
	for _, tc := range []testCase{
		{
			name:    "invalid hash function",
			hash:    "SHA1",
			privKey: validPrivKey,
			salt:    0,
		},
		{
			name: "invalid exponent",
			hash: "SHA256",
			salt: 0,
			privKey: &rsa.PrivateKey{
				D: validPrivKey.D,
				PublicKey: rsa.PublicKey{
					N: validPrivKey.N,
					E: 8,
				},
				Primes:      validPrivKey.Primes,
				Precomputed: validPrivKey.Precomputed,
			},
		},
		{
			name: "invalid modulus",
			hash: "SHA256",
			salt: 0,
			privKey: &rsa.PrivateKey{
				D: validPrivKey.D,
				PublicKey: rsa.PublicKey{
					N: big.NewInt(5),
					E: validPrivKey.E,
				},
				Primes:      validPrivKey.Primes,
				Precomputed: validPrivKey.Precomputed,
			},
		},
		{
			name:    "invalid salt",
			hash:    "SHA256",
			salt:    -1,
			privKey: validPrivKey,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := signature.New_RSA_SSA_PSS_Signer(tc.hash, tc.salt, tc.privKey); err == nil {
				t.Errorf("New_RSA_SSA_PSS_Signer() err = nil, want error")
			}
			if _, err := signature.New_RSA_SSA_PSS_Verifier(tc.hash, tc.salt, &tc.privKey.PublicKey); err == nil {
				t.Errorf("New_RSA_SSA_PSS_Verifier() err = nil, want error")
			}
		})
	}
}

type rsaSSAPSSSuite struct {
	testutil.WycheproofSuite
	TestGroups []*rsaSSAPSSGroup `json:"testGroups"`
}

type rsaSSAPSSGroup struct {
	testutil.WycheproofGroup
	SHA        string            `json:"sha"`
	MGFSHA     string            `json:"mgfSha"`
	SaltLength int               `json:"sLen"`
	E          testutil.HexBytes `json:"e"`
	N          testutil.HexBytes `json:"N"`
	Tests      []*rsaSSAPSSCase  `json:"tests"`
}

type rsaSSAPSSCase struct {
	testutil.WycheproofCase
	Message   testutil.HexBytes `json:"msg"`
	Signature testutil.HexBytes `json:"sig"`
}

func TestRSASSAPSSWycheproofCases(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	ranTestCount := 0
	vectorsFiles := []string{
		"rsa_pss_2048_sha512_256_mgf1_28_test.json",
		"rsa_pss_2048_sha512_256_mgf1_32_test.json",
		"rsa_pss_2048_sha256_mgf1_0_test.json",
		"rsa_pss_2048_sha256_mgf1_32_test.json",
		"rsa_pss_3072_sha256_mgf1_32_test.json",
		"rsa_pss_4096_sha256_mgf1_32_test.json",
		"rsa_pss_4096_sha512_mgf1_32_test.json",
	}
	for _, v := range vectorsFiles {
		suite := &rsaSSAPSSSuite{}
		if err := testutil.PopulateSuite(suite, v); err != nil {
			t.Fatalf("failed populating suite: %s", err)
		}
		for _, group := range suite.TestGroups {
			sigHash := subtle.ConvertHashName(group.SHA)
			if sigHash == "" {
				continue
			}
			pubKey := &rsa.PublicKey{
				E: int(new(big.Int).SetBytes(group.E).Uint64()),
				N: new(big.Int).SetBytes(group.N),
			}
			verifier, err := signature.New_RSA_SSA_PSS_Verifier(sigHash, group.SaltLength, pubKey)
			if err != nil {
				t.Fatalf("New_RSA_SSA_PSS_Verifier() err = %v, want nil", err)
			}
			for _, test := range group.Tests {
				if (test.CaseID == 67 || test.CaseID == 68) && v == "rsa_pss_2048_sha256_mgf1_0_test.json" {
					// crypto/rsa will interpret zero length salt and parse the salt length from signature.
					// Since this test cases use a zero salt length as a parameter, even if a different parameter
					// is provided, Golang will interpret it and parse the salt directly from the signature.
					continue
				}
				ranTestCount++
				caseName := fmt.Sprintf("%s: %s-%s-%s-%d:Case-%d", v, group.Type, group.SHA, group.MGFSHA, group.SaltLength, test.CaseID)
				t.Run(caseName, func(t *testing.T) {
					err := verifier.Verify(test.Signature, test.Message)
					switch test.Result {
					case "valid":
						if err != nil {
							t.Errorf("Verify() err = %, want nil", err)
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
	if ranTestCount < 578 {
		t.Errorf("ranTestCount > %d, want > %d", ranTestCount, 578)
	}
}
