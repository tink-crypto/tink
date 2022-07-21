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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/curve25519"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/testutil"
)

func TestComputeSharedSecretX25519WithRFCTestVectors(t *testing.T) {
	// Test vectors are defined at
	// https://datatracker.ietf.org/doc/html/rfc7748#section-6.1.
	tests := []struct {
		priv string
		pub  string
	}{
		{"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"},
		{"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"},
	}
	shared := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			priv, err := hex.DecodeString(test.priv)
			if err != nil {
				t.Fatalf("DecodeString(priv): got err %q, want nil", err)
			}
			pub, err := hex.DecodeString(test.pub)
			if err != nil {
				t.Fatalf("DecodeString(pub): got err %q, want nil", err)
			}

			gotShared, err := subtle.ComputeSharedSecretX25519(priv, pub)
			if err != nil {
				t.Fatalf("ComputeSharedSecretX25519(priv, pub): got err %q, want nil", err)
			}
			if got, want := hex.EncodeToString(gotShared), shared; got != want {
				t.Errorf("ComputeSharedSecretX25519(shared): got %v, want %v", got, want)
			}
		})
	}
}

type x25519Suite struct {
	testutil.WycheproofSuite
	TestGroups []*x25519Group `json:"testGroups"`
}

type x25519Group struct {
	testutil.WycheproofGroup
	Curve string        `json:"curve"`
	Tests []*x25519Case `json:"tests"`
}

type x25519Case struct {
	testutil.WycheproofCase
	Public  string   `json:"public"`
	Private string   `json:"private"`
	Shared  string   `json:"shared"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

func TestComputeSharedSecretX25519WithWycheproofVectors(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)

	suite := new(x25519Suite)
	if err := testutil.PopulateSuite(suite, "x25519_test.json"); err != nil {
		t.Fatalf("testutil.PopulateSuite: %v", err)
	}

	for _, group := range suite.TestGroups {
		if group.Curve != "curve25519" {
			continue
		}

		for _, test := range group.Tests {
			t.Run(fmt.Sprintf("%d", test.CaseID), func(t *testing.T) {
				pub, err := hex.DecodeString(test.Public)
				if err != nil {
					t.Fatalf("DecodeString(pub): got err %q, want nil", err)
				}
				priv, err := hex.DecodeString(test.Private)
				if err != nil {
					t.Fatalf("DecodeString(priv): got err %q, want nil", err)
				}

				gotShared, err := subtle.ComputeSharedSecretX25519(priv, pub)
				// ComputeSharedSecretX25519 fails on low order public values.
				wantErr := false
				for _, flag := range test.Flags {
					if flag == "LowOrderPublic" {
						wantErr = true
					}
				}

				if wantErr {
					if err == nil {
						t.Error("ComputeSharedSecretX25519(priv, pub): got success, want err")
					}
				} else {
					if err != nil {
						t.Errorf("ComputeSharedSecretX25519(priv, pub): got err %q, want nil", err)
					}
					if got, want := hex.EncodeToString(gotShared), test.Shared; got != want {
						t.Errorf("ComputeSharedSecretX25519(shared): got %v, want %v", got, want)
					}
				}
			})
		}
	}
}

func TestComputeSharedSecretX25519Fails(t *testing.T) {
	pubs := []string{
		// Should fail on non-32-byte inputs.
		"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c",
		"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a2a",
		// Should fail on low order points, from Sodium
		// https://github.com/jedisct1/libsodium/blob/65621a1059a37d/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L11-L70.
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}

	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}

	for i, pubHex := range pubs {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			pub, err := hex.DecodeString(pubHex)
			if err != nil {
				t.Fatalf("DecodeString(pub): got err %q, want nil", err)
			}
			if _, err := subtle.ComputeSharedSecretX25519(priv, pub); err == nil {
				t.Error("ComputeSharedSecretX25519(priv, pub): got success, want err")
			}
		})
	}
}

func TestPublicFromPrivateX25519WithRFCTestVectors(t *testing.T) {
	// Test vectors are defined at
	// https://datatracker.ietf.org/doc/html/rfc7748#section-6.1.
	tests := []struct {
		priv string
		pub  string
	}{
		{"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"},
		{"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			priv, err := hex.DecodeString(test.priv)
			if err != nil {
				t.Fatalf("DecodeString(priv): got err %q, want nil", err)
			}
			gotPub, err := subtle.PublicFromPrivateX25519(priv)
			if err != nil {
				t.Fatalf("PublicFromPrivateX25519(priv): got err %q, want nil", err)
			}
			if got, want := hex.EncodeToString(gotPub), test.pub; got != want {
				t.Errorf("PublicFromPrivateX25519(priv): got %s, want %s", got, want)
			}
		})
	}
}

func TestPublicFromPrivateX25519Fails(t *testing.T) {
	// PublicFromPrivateX25519 fails on non-32-byte private keys.
	privs := []string{
		"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c",
		"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb95",
	}

	for i, priv := range privs {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			priv, err := hex.DecodeString(priv)
			if err != nil {
				t.Fatalf("DecodeString(priv): got err %q, want nil", err)
			}
			if _, err := subtle.PublicFromPrivateX25519(priv); err == nil {
				t.Error("PublicFromPrivateX25519(priv): got success, want err")
			}
		})
	}
}
