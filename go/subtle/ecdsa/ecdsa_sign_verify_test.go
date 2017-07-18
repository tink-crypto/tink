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
  // "reflect"
  "github.com/google/tink/go/subtle/random"
  "github.com/google/tink/go/subtle/ecdsa"
  subtleUtil "github.com/google/tink/go/subtle/util"
  "github.com/google/tink/go/util/util"
  "github.com/google/tink/go/util/testutil"
  ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
  commonpb "github.com/google/tink/proto/common_go_proto"
)

var _ = fmt.Println

func TestSignVerify(t *testing.T) {
  data := random.GetRandomBytes(20)
  priv := testutil.NewP256EcdsaPrivateKey()
  signer, err := ecdsa.NewEcdsaSign(priv)
  if err != nil {
    t.Errorf("unexpected error when creating EcdsaSign: %s", err)
  }
  verifier, err := ecdsa.NewEcdsaVerify(priv.PublicKey)
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
  f, err := os.Open("../../testdata/ecdsa_test.json")
  if err != nil {
    t.Errorf("cannot open file: %s", err)
  }
  parser := json.NewDecoder(f)
  content := new(testData)
  if err := parser.Decode(content); err != nil {
    t.Errorf("cannot decode content of file: %s", err)
  }
  for _, g := range content.TestGroups {
    hashType := subtleUtil.HashNameToHashType(g.Sha)
    curveType := subtleUtil.CurveNameToCurveType(g.Key.Curve)
    if hashType == commonpb.HashType_UNKNOWN_HASH ||
        curveType == commonpb.EllipticCurveType_UNKNOWN_CURVE {
      continue
    }
    encoding := ecdsapb.EcdsaSignatureEncoding_DER
    x, err := subtleUtil.NewBigIntFromHex(g.Key.Wx)
    if err != nil {
      t.Errorf("cannot decode wx: %s", err)
    }
    y, err := subtleUtil.NewBigIntFromHex(g.Key.Wy)
    if err != nil {
      t.Errorf("cannot decode wy: %s", err)
    }
    pub := util.NewEcdsaPublicKey(0, hashType, curveType, encoding, x.Bytes(), y.Bytes())
    verifier, err := ecdsa.NewEcdsaVerify(pub)
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