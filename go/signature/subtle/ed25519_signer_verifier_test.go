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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/ed25519"

	subtleSignature "github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
)

func TestED25519Deterministic(t *testing.T) {
	data := random.GetRandomBytes(20)
	public, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("key generation error: %s", err)
	}

	// Use the private key and public key directly to create new instances
	signer, verifier, err := newSignerVerifier(t, &priv, &public)
	if err != nil {
		t.Errorf("unexpected error when creating ED25519 Signer and Verifier: %s", err)
	}
	sign1, err := signer.Sign(data)
	if err != nil {
		t.Errorf("unexpected error when signing: %s", err)
	}
	if err := verifier.Verify(sign1, data); err != nil {
		t.Errorf("unexpected error when verifying: %s", err)
	}

	sign2, err := signer.Sign(data)
	if err != nil {
		t.Errorf("unexpected error when signing: %s", err)
	}
	if err := verifier.Verify(sign2, data); err != nil {
		t.Errorf("unexpected error when verifying: %s", err)
	}
	if !bytes.Equal(sign1, sign2) {
		t.Error("deterministic signature check failure")
	}

}

func TestEd25519VerifyModifiedSignature(t *testing.T) {
	data := random.GetRandomBytes(20)
	public, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("key generation error: %s", err)
	}
	// Use the private key and public key directly to create new instances
	signer, verifier, err := newSignerVerifier(t, &priv, &public)
	if err != nil {
		t.Fatalf("failed to create new signer verifier: %v", err)
	}

	sign, err := signer.Sign(data)
	if err != nil {
		t.Errorf("unexpected error when signing: %s", err)
	}

	for i := 0; i < len(sign); i++ {
		for j := 0; j < 8; j++ {
			sign[i] = byte(sign[i] ^ (1 << uint32(j)))
			if err := verifier.Verify(sign, data); err == nil {
				t.Errorf("unexpected error when verifying: %s", err)
			}
		}
	}
}
func TestEd25519VerifyModifiedMessage(t *testing.T) {
	data := random.GetRandomBytes(20)
	public, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("key generation error: %s", err)
	}

	// Use the private key and public key directly to create new instances
	signer, verifier, err := newSignerVerifier(t, &priv, &public)
	if err != nil {
		t.Fatalf("failed to create new signer verifier: %v", err)
	}

	sign, err := signer.Sign(data)
	if err != nil {
		t.Errorf("unexpected error when signing: %s", err)
	}

	for i := 0; i < len(data); i++ {
		for j := 0; j < 8; j++ {
			data[i] = byte(data[i] ^ (1 << uint32(j)))
			if err := verifier.Verify(sign, data); err == nil {
				t.Errorf("unexpected error when verifying: %s", err)
			}
		}
	}
}
func TestED25519SignVerify(t *testing.T) {
	public, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("key generation error: %s", err)
	}

	// Use the private key and public key directly to create new instances
	signer, verifier, err := newSignerVerifier(t, &priv, &public)
	if err != nil {
		t.Errorf("unexpected error when creating ED25519 Signer and Verifier: %s", err)
	}
	for i := 0; i < 100; i++ {
		data := random.GetRandomBytes(20)
		signature, err := signer.Sign(data)
		if err != nil {
			t.Errorf("unexpected error when signing: %s", err)
		}
		if err := verifier.Verify(signature, data); err != nil {
			t.Errorf("unexpected error when verifying: %s", err)
		}

		// Use byte slices to create new instances
		signer, err = subtleSignature.NewED25519Signer(priv[:ed25519.SeedSize])
		if err != nil {
			t.Errorf("unexpected error when creating ED25519 Signer: %s", err)
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

func TestED25519WycheproofCases(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)

	suite := new(ed25519Suite)
	if err := testutil.PopulateSuite(suite, "eddsa_test.json"); err != nil {
		t.Fatalf("failed populating suite: %s", err)
	}
	for _, group := range suite.TestGroups {
		private := ed25519.PrivateKey(group.Key.SK)
		public := ed25519.PrivateKey(group.Key.PK)
		signer, err := subtleSignature.NewED25519Signer(private)
		if err != nil {
			continue
		}
		verifier, err := subtleSignature.NewED25519Verifier(public)
		if err != nil {
			continue
		}
		for _, test := range group.Tests {
			caseName := fmt.Sprintf("Sign-%s-%s:Case-%d", suite.Algorithm, group.Type, test.CaseID)
			t.Run(caseName, func(t *testing.T) {
				got, err := signer.Sign(test.Message)
				switch test.Result {
				case "valid":
					if err != nil {
						t.Fatalf("ED25519Signer.Sign() failed in a valid test case: %s", err)
					}
					if !bytes.Equal(got, test.Signature) {
						// Ed25519 is deterministic.
						// Getting an alternative signature may leak the private key.
						// This is especially the case if an attacker can also learn the valid signature.
						t.Fatalf("ED25519Signer.Sign() = %s, want = %s", hex.EncodeToString(got), hex.EncodeToString(test.Signature))
					}
				case "invalid":
					if err == nil && bytes.Equal(got, test.Signature) {
						t.Fatalf("ED25519Signer.Sign() produced a matching signature in an invalid test case.")
					}
				default:
					t.Fatalf("unrecognized result: %q", test.Result)
				}
			})

			caseName = fmt.Sprintf("Verify-%s-%s:Case-%d", suite.Algorithm, group.Type, test.CaseID)
			t.Run(caseName, func(t *testing.T) {
				err := verifier.Verify(test.Signature, test.Message)
				switch test.Result {
				case "valid":
					if err != nil {
						t.Fatalf("ED25519Verifier.Verify() failed in a valid test case: %s", err)
					}
				case "invalid":
					if err == nil {
						t.Fatal("ED25519Verifier.Verify() succeeded in an invalid test case.")
					}
				default:
					t.Fatalf("unsupported test result: %q", test.Result)
				}
			})
		}
	}
}

func newSignerVerifier(t *testing.T, pvtKey *ed25519.PrivateKey, pubKey *ed25519.PublicKey) (*subtleSignature.ED25519Signer, *subtleSignature.ED25519Verifier, error) {
	t.Helper()
	signer, err := subtleSignature.NewED25519SignerFromPrivateKey(pvtKey)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := subtleSignature.NewED25519VerifierFromPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}
	return signer, verifier, nil
}
