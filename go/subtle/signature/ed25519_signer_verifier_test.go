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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/google/tink/go/subtle/random"
	subtleSignature "github.com/google/tink/go/subtle/signature"
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

type testDataED25519 struct {
	Algorithm        string
	GeneratorVersion string
	NumberOfTests    uint32
	TestGroups       []*testGroupED25519
}

type testGroupED25519 struct {
	KeyDer string
	KeyPem string
	Sha    string
	Type   string
	Key    *testKeyED25519
	Tests  []*testcaseED25519
}

type testKeyED25519 struct {
	Sk string
	Pk string
}

type testcaseED25519 struct {
	Comment string
	Msg     string
	Result  string
	Sig     string
	TcID    uint32
}

func TestVectorsED25519(t *testing.T) {
	// signing tests are same between ecdsa and ed25519
	f, err := os.Open(os.Getenv("TEST_SRCDIR") + "/wycheproof/testvectors/eddsa_test.json")
	if err != nil {
		t.Fatalf("cannot open file: %s", err)
	}
	parser := json.NewDecoder(f)
	content := new(testDataED25519)
	if err := parser.Decode(content); err != nil {
		t.Fatalf("cannot decode content of file: %s", err)
	}
	for _, g := range content.TestGroups {
		pvtKey, err := hex.DecodeString(g.Key.Sk)
		if err != nil {
			t.Fatalf("cannot decode sk key: %s", err)
		}
		pubKey, err := hex.DecodeString(g.Key.Pk)
		if err != nil {
			t.Fatalf("cannot decode private key: %s", err)
		}

		private := ed25519.PrivateKey(pvtKey)
		public := ed25519.PrivateKey(pubKey)
		signer, err := subtleSignature.NewED25519Signer(private)
		if err != nil {
			continue
		}
		verifier, err := subtleSignature.NewED25519Verifier(public)
		if err != nil {
			continue
		}
		for _, tc := range g.Tests {
			message, err := hex.DecodeString(tc.Msg)
			if err != nil {
				t.Errorf("cannot decode message in test case %d: %s", tc.TcID, err)
			}
			sig, err := hex.DecodeString(tc.Sig)
			if err != nil {
				t.Errorf("cannot decode signature in test case %d: %s", tc.TcID, err)
			}
			got, err := signer.Sign(message)
			if tc.Result == "valid" && err != nil {
				t.Errorf("sign failed in test case %d: with error %s", tc.TcID, err)
			}
			if tc.Result == "valid" && err == nil && !bytes.Equal(sig, got) {
				// Ed25519 is deterministic.
				// Getting an alternative signature may leak the private key.
				// This is especially the case if an attacker can also learn the valid signature.
				t.Errorf("sign failed in test case %d: invalid signature generated %s", tc.TcID, hex.EncodeToString(got))
			}
			if tc.Result == "invalid" && err == nil && bytes.Equal(sig, got) {
				t.Errorf("sign failed in test case %d: invalid signature generated", tc.TcID)
			}
			err = verifier.Verify(sig, message)
			if tc.Result == "valid" && err != nil {
				t.Errorf("verify failed in test case %d: valid signature is rejected with error %s", tc.TcID, err)
			}
			if tc.Result == "invalid" && err == nil {
				t.Errorf("verify failed in test case %d: invalid signature is accepted", tc.TcID)
			}
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
