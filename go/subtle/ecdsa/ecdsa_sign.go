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
package ecdsa

import (
  "fmt"
  "math/big"
  "crypto/ecdsa"
  "crypto/rand"
  "github.com/google/tink/go/tink/tink"
  "github.com/google/tink/go/subtle/util"
  ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
  commonpb "github.com/google/tink/proto/common_go_proto"
)

// ecdsaSign is an implementation of PublicKeySign for ECDSA.
// At the moment, the implementation only accepts DER encoding.
type ecdsaSign struct {
  privateKey *ecdsa.PrivateKey
  hashType commonpb.HashType
  encoding ecdsapb.EcdsaSignatureEncoding
}

// Assert that ecdsaSign implements the PublicKeySign interface.
var _ tink.PublicKeySign = (*ecdsaSign)(nil)

// NewEcdsaSign creates a new instance of EcdsaSign.
func NewEcdsaSign(privateKey *ecdsapb.EcdsaPrivateKey) (*ecdsaSign, error) {
  if err := ValidatePrivateKey(privateKey); err != nil {
    return nil, fmt.Errorf("ecdsa_sign: %s", err)
  }
  params := privateKey.PublicKey.Params
  publicKey := ecdsa.PublicKey{Curve: util.GetCurve(params.Curve), X: nil, Y: nil}
  d := new(big.Int).SetBytes(privateKey.KeyValue)
  return &ecdsaSign{
    privateKey: &ecdsa.PrivateKey{PublicKey: publicKey, D: d},
    hashType: params.HashType,
    encoding: params.Encoding,
  }, nil
}

// Sign computes a signature for the given data.
func (e *ecdsaSign) Sign(data []byte) ([]byte, error) {
  hashed := util.GetHash(e.hashType, data)
  r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, hashed)
  if err != nil {
    return nil, fmt.Errorf("ecdsa_sign: signing failed: %s", err)
  }
  // format the signature
  sig := NewSignature(r, s)
  ret, err := sig.Encode(e.encoding)
  if err != nil {
    return nil, fmt.Errorf("ecdsa_sign: signing failed: %s", err)
  }
  return ret, nil
}