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
  "github.com/google/tink/go/tink/tink"
  "github.com/google/tink/go/subtle/util"
  ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
  commonpb "github.com/google/tink/proto/common_go_proto"
)

var ErrInvalidSignature = fmt.Errorf("ecdsa_verify: invalid signature")

// ecdsaVerify is an implementation of PublicKeyVerify for ECDSA.
// At the moment, the implementation only accepts signatures with strict DER encoding.
type ecdsaVerify struct {
  publicKey *ecdsa.PublicKey
  hashType commonpb.HashType
  encoding ecdsapb.EcdsaSignatureEncoding
}

// Assert that ecdsaVerify implements the PublicKeyVerify interface.
var _ tink.PublicKeyVerify = (*ecdsaVerify)(nil)

// NewEcdsaVerify creates a new instance of ecdsaVerify.
func NewEcdsaVerify(publicKey *ecdsapb.EcdsaPublicKey) (*ecdsaVerify, error) {
  if err := ValidatePublicKey(publicKey); err != nil {
    return nil, fmt.Errorf("ecdsa_sign: %s", err)
  }
  params := publicKey.Params
  x := new(big.Int).SetBytes(publicKey.X)
  y := new(big.Int).SetBytes(publicKey.Y)
  return &ecdsaVerify{
    publicKey: &ecdsa.PublicKey{Curve: util.GetCurve(params.Curve), X: x, Y: y},
    hashType: params.HashType,
    encoding: params.Encoding,
  }, nil
}

// Verify verifies whether the given signature is valid for the given data.
// It returns an error if the signature is not valid; nil otherwise.
func (e *ecdsaVerify) Verify(signatureBytes []byte, data []byte) error {
  signature, err := DecodeSignature(signatureBytes, e.encoding)
  if err != nil {
    return ErrInvalidSignature
  }
  hashed := util.GetHash(e.hashType, data)
  valid := ecdsa.Verify(e.publicKey, hashed, signature.R, signature.S)
  if valid {
    return nil
  }
  return ErrInvalidSignature
}

