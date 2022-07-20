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
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"testing"

	subtleSignature "github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/testutil"
)

func TestSignVerify(t *testing.T) {
	data := random.GetRandomBytes(20)
	hash := "SHA256"
	curve := "NIST_P256"
	encodings := []string{"DER", "IEEE_P1363"}
	for _, encoding := range encodings {
		priv, _ := ecdsa.GenerateKey(subtle.GetCurve(curve), rand.Reader)
		// Use the private key and public key directly to create new instances
		signer, err := subtleSignature.NewECDSASignerFromPrivateKey(hash, encoding, priv)
		if err != nil {
			t.Errorf("unexpected error when creating ECDSASigner: %s", err)
		}
		verifier, err := subtleSignature.NewECDSAVerifierFromPublicKey(hash, encoding, &priv.PublicKey)
		if err != nil {
			t.Errorf("unexpected error when creating ECDSAVerifier: %s", err)
		}
		signature, err := signer.Sign(data)
		if err != nil {
			t.Errorf("unexpected error when signing: %s", err)
		}
		if err := verifier.Verify(signature, data); err != nil {
			t.Errorf("unexpected error when verifying: %s", err)
		}

		// Use byte slices to create new instances
		signer, err = subtleSignature.NewECDSASigner(hash, curve, encoding, priv.D.Bytes())
		if err != nil {
			t.Errorf("unexpected error when creating ECDSASigner: %s", err)
		}
		verifier, err = subtleSignature.NewECDSAVerifier(hash, curve, encoding, priv.X.Bytes(), priv.Y.Bytes())
		if err != nil {
			t.Errorf("unexpected error when creating ECDSAVerifier: %s", err)
		}
		signature, err = signer.Sign(data)
		if err != nil {
			t.Errorf("unexpected error when signing: %s", err)
		}
		if err = verifier.Verify(signature, data); err != nil {
			t.Errorf("unexpected error when verifying: %s", err)
		}
	}
}

func TestECDSAInvalidPublicKey(t *testing.T) {
	if _, err := subtleSignature.NewECDSAVerifier("SHA256", "NIST_P256", "IEEE_P1363", []byte{0, 32, 0}, []byte{0, 32}); err == nil {
		t.Errorf("subtleSignature.NewECDSAVerifier() err = nil, want error")
	}
}

func TestECDSAInvalidCurve(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(subtle.GetCurve("NIST_P256"), rand.Reader)
	if _, err := subtleSignature.NewECDSAVerifier("SHA256", "INVALID", "IEEE_P1363", priv.X.Bytes(), priv.Y.Bytes()); err == nil {
		t.Errorf("subtleSignature.NewECDSAVerifier() err = nil, want error")
	}
}

func TestECDSAWycheproofCases(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)

	vectors := []struct {
		Filename string
		Encoding string
	}{
		{"ecdsa_test.json", "DER"},
		{"ecdsa_secp256r1_sha256_p1363_test.json", "IEEE_P1363"},
		{"ecdsa_secp384r1_sha512_p1363_test.json", "IEEE_P1363"},
		{"ecdsa_secp521r1_sha512_p1363_test.json", "IEEE_P1363"},
	}

	for _, v := range vectors {
		suite := new(ecdsaSuite)
		if err := testutil.PopulateSuite(suite, v.Filename); err != nil {
			t.Fatalf("failed populating suite: %s", err)
		}
		for _, group := range suite.TestGroups {
			hash := subtle.ConvertHashName(group.SHA)
			curve := subtle.ConvertCurveName(group.Key.Curve)
			if hash == "" || curve == "" {
				continue
			}
			x, err := subtle.NewBigIntFromHex(group.Key.Wx)
			if err != nil {
				t.Errorf("cannot decode wx: %s", err)
				continue
			}
			y, err := subtle.NewBigIntFromHex(group.Key.Wy)
			if err != nil {
				t.Errorf("cannot decode wy: %s", err)
				continue
			}
			verifier, err := subtleSignature.NewECDSAVerifier(hash, curve, v.Encoding, x.Bytes(), y.Bytes())
			if err != nil {
				continue
			}
			for _, test := range group.Tests {
				caseName := fmt.Sprintf("%s-%s:Case-%d", group.Type, group.SHA, test.CaseID)
				t.Run(caseName, func(t *testing.T) {
					err := verifier.Verify(test.Signature, test.Message)
					switch test.Result {
					case "valid":
						if err != nil {
							t.Fatalf("ECDSAVerifier.Verify() failed in a valid test case: %s", err)
						}
					case "invalid":
						if err == nil {
							t.Fatalf("ECDSAVerifier.Verify() succeeded in an invalid test case")
						}
					case "acceptable":
						// TODO(ckl): Inspect flags to appropriately handle acceptable test cases.
					default:
						t.Fatalf("unsupported test result: %q", test.Result)
					}
				})
			}
		}
	}
}
