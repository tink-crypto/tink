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
package ecdsa_test

import (
  "fmt"
  "testing"
  "os"
  "encoding/json"
  "encoding/hex"
  "crypto/ecdsa"
  "crypto/rand"
  "github.com/google/tink/go/subtle/random"
  subtleEcdsa "github.com/google/tink/go/subtle/ecdsa"
  "github.com/google/tink/go/subtle/subtleutil"
)

func TestSignVerify(t *testing.T) {
  data := random.GetRandomBytes(20)
  hash := "SHA256"
  curve := "NIST_P256"
  encoding := "DER"
  priv, _ := ecdsa.GenerateKey(subtleutil.GetCurve(curve), rand.Reader)
  // Use the private key and public key directly to create new instances
  signer, err := subtleEcdsa.NewEcdsaSignFromPrivateKey(hash, encoding, priv)
  if err != nil {
    t.Errorf("unexpected error when creating EcdsaSign: %s", err)
  }
  verifier, err := subtleEcdsa.NewEcdsaVerifyFromPublicKey(hash, encoding, &priv.PublicKey)
  if err != nil {
    t.Errorf("unexpected error when creating EcdsaVerify: %s", err)
  }
  signature, err := signer.Sign(data)
  if err != nil {
    t.Errorf("unexpected error when signing: %s", err)
  }
  err = verifier.Verify(signature, data)
  if err != nil {
    t.Errorf("unexpected error when verifying: %s", err)
  }

  // Use byte slices to create new instances
  signer, err = subtleEcdsa.NewEcdsaSign(hash, curve, encoding, priv.D.Bytes())
  if err != nil {
    t.Errorf("unexpected error when creating EcdsaSign: %s", err)
  }
  verifier, err = subtleEcdsa.NewEcdsaVerify(hash, curve, encoding, priv.X.Bytes(), priv.Y.Bytes())
  if err != nil {
    t.Errorf("unexpected error when creating EcdsaVerify: %s", err)
  }
  signature, err = signer.Sign(data)
  if err != nil {
    t.Errorf("unexpected error when signing: %s", err)
  }
  err = verifier.Verify(signature, data)
  if err != nil {
    t.Errorf("unexpected error when verifying: %s", err)
  }
}

type testData struct {
  Algorithm string
  GeneratorVersion string
  NumberOfTests uint32
  TestGroups []*testGroup
}

type testGroup struct {
  KeyDer string
  KeyPem string
  Sha string
  Type string
  Key *testKey
  Tests []*testcase
}

type testKey struct {
  Curve string
  Type string
  Wx string
  Wy string
}

type testcase struct {
  Comment string
  Message string
  Result string
  Sig string
  TcId uint32
}

func TestVectors(t *testing.T) {
  f, err := os.Open("../../../wycheproof/testvectors/ecdsa_test.json")
  if err != nil {
    t.Errorf("cannot open file: %s", err)
  }
  parser := json.NewDecoder(f)
  content := new(testData)
  if err := parser.Decode(content); err != nil {
    t.Errorf("cannot decode content of file: %s", err)
  }
  for _, g := range content.TestGroups {
    hash := subtleutil.ConvertHashName(g.Sha)
    curve := subtleutil.ConvertCurveName(g.Key.Curve)
    if hash == "" || curve == "" {
      continue
    }
    encoding := "DER"
    x, err := subtleutil.NewBigIntFromHex(g.Key.Wx)
    if err != nil {
      t.Errorf("cannot decode wx: %s", err)
    }
    y, err := subtleutil.NewBigIntFromHex(g.Key.Wy)
    if err != nil {
      t.Errorf("cannot decode wy: %s", err)
    }
    verifier, err := subtleEcdsa.NewEcdsaVerify(hash, curve, encoding, x.Bytes(), y.Bytes())
    if err != nil {
      continue
    }
    for _, tc := range g.Tests {
      message, err := hex.DecodeString(tc.Message)
      if err != nil {
        t.Errorf("cannot decode message in test case %d: %s", tc.TcId, err)
      }
      sig, err := hex.DecodeString(tc.Sig)
      if err != nil {
        t.Errorf("cannot decode signature in test case %d: %s", tc.TcId, err)
      }
      err = verifier.Verify(sig, message)
      if (tc.Result == "valid" && err != nil) ||
          (tc.Result == "invalid" && err == nil) {
        fmt.Println("failed in test case ", tc.TcId, err)
      }
    }
  }
}