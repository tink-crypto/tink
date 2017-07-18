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
  "math/big"
  "encoding/asn1"
  . "github.com/google/tink/go/subtle/ecdsa"
  "github.com/google/tink/go/subtle/random"
  "github.com/google/tink/go/util/util"
  commonpb "github.com/google/tink/proto/common_go_proto"
  ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
)

var _ = fmt.Println

func TestEncodeDecode(t *testing.T) {
  nTest := 1000
  for i := 0; i < nTest; i++ {
    sig := newRandomSignature()
    encoding := ecdsapb.EcdsaSignatureEncoding_DER
    encoded, err := sig.Encode(encoding)
    if err != nil {
      t.Errorf("unexpected error during encoding: %s", err)
    }
    // first byte is 0x30
    if encoded[0] != byte(0x30) {
      t.Errorf("first byte is incorrect, expected 48, got %v", encoded[0])
    }
    // tag is 2
    if encoded[2] != byte(2) || encoded[4+encoded[3]] != byte(2) {
      t.Errorf("expect tag to be 2 (integer), got %d and %d", encoded[2], encoded[4+encoded[3]])
    }
    // length
    if len(encoded) != int(encoded[1])+2 {
      t.Errorf("incorrect length, expected %d, got %d", len(encoded), encoded[1]+2)
    }
    decodedSig, err := DecodeSignature(encoded, encoding)
    if err != nil {
      t.Errorf("unexpected error during decoding: %s", err)
    }
    if decodedSig.R.Cmp(sig.R) != 0 || decodedSig.S.Cmp(sig.S) != 0 {
      t.Errorf("decoded signature doesn't match original value")
    }
  }
}

func TestEncodeWithInvalidInput(t *testing.T) {
  sig := newRandomSignature()
  _, err := sig.Encode(ecdsapb.EcdsaSignatureEncoding_UNKNOWN_ENCODING)
  if err == nil {
    t.Errorf("expect an error when encoding is invalid")
  }
}

func TestDecodeWithInvalidInput(t *testing.T) {
  var sig *EcdsaSignature
  var encoded []byte
  encoding := ecdsapb.EcdsaSignatureEncoding_DER

  // modified first byte
  sig = newRandomSignature()
  encoded, _ = sig.Encode(encoding)
  encoded[0] = 0x31
  if _, err := DecodeSignature(encoded, encoding); err == nil {
    t.Errorf("expect an error when first byte is not 0x30")
  }
  // modified tag
  sig = newRandomSignature()
  encoded, _ = sig.Encode(encoding)
  encoded[2] = encoded[2] + 1
  if _, err := DecodeSignature(encoded, encoding); err == nil {
    t.Errorf("expect an error when tag is modified")
  }
  // modified length
  sig = newRandomSignature()
  encoded, _ = sig.Encode(encoding)
  encoded[1] = encoded[1] + 1
  if _, err := DecodeSignature(encoded, encoding); err == nil {
    t.Errorf("expect an error when length is modified")
  }
  // append unused 0s
  sig = newRandomSignature()
  encoded, _ = sig.Encode(encoding)
  tmp := make([]byte, len(encoded)+4)
  copy(tmp, encoded)
  if _, err := DecodeSignature(tmp, encoding); err == nil {
    t.Errorf("expect an error when unused 0s are appended to signature")
  }
  // a struct with three numbers
  randomStruct := struct{X, Y, Z *big.Int}{
    X: new(big.Int).SetBytes(random.GetRandomBytes(32)),
    Y: new(big.Int).SetBytes(random.GetRandomBytes(32)),
    Z: new(big.Int).SetBytes(random.GetRandomBytes(32)),
  }
  encoded, _ = asn1.Marshal(randomStruct)
  if _, err := DecodeSignature(encoded, encoding); err == nil {
    t.Errorf("expect an error when input is not an EcdsaSignature")
  }
}

func TestValidatePrivateKey(t *testing.T) {
  // valid
  params := genValidParams()
  for i := 0; i < len(params); i++ {
    pub := new(ecdsapb.EcdsaPublicKey)
    pub.Params = params[i]
    priv := new(ecdsapb.EcdsaPrivateKey)
    priv.PublicKey = pub
    if err := ValidatePrivateKey(priv); err != nil {
      t.Errorf("unexpected error for valid private key: %s, i = %d", err, i)
    }
  }
  // nil private key
  if err := ValidatePrivateKey(nil); err == nil {
    t.Errorf("expected an error when private key is nil")
  }
  // nil public key
  if err := ValidatePrivateKey(util.NewEcdsaPrivateKey(0, nil, nil)); err == nil {
    t.Errorf("expected an error when public key is nil")
  }
  // invalid params
  params = genInvalidParams()
  for i := 0; i < len(params); i++ {
    pub := new(ecdsapb.EcdsaPublicKey)
    pub.Params = params[i]
    priv := new(ecdsapb.EcdsaPrivateKey)
    priv.PublicKey = pub
    if err := ValidatePrivateKey(priv); err == nil {
      t.Errorf("expected an error when private key is invalid, i = %d", i)
    }
  }
}

func TestValidatePublicKey(t *testing.T) {
  // valid
  params := genValidParams()
  for i := 0; i < len(params); i++ {
    pub := new(ecdsapb.EcdsaPublicKey)
    pub.Params = params[i]
    if err := ValidatePublicKey(pub); err != nil {
      t.Errorf("unexpected error for valid public key: %s, i = %d", err, i)
    }
  }
  // nil public key
  if err := ValidatePublicKey(nil); err == nil {
    t.Errorf("expected an error when public key is nil")
  }
  // invalid params
  params = genInvalidParams()
  for i := 0; i < len(params); i++ {
    pub := new(ecdsapb.EcdsaPublicKey)
    pub.Params = params[i]
    if err := ValidatePublicKey(pub); err == nil {
      t.Errorf("expected an error when public key is invalid, i = %d", i)
    }
  }
}

func TestValidateParams(t *testing.T) {
  params := genValidParams()
  for i := 0; i < len(params); i++ {
    if err := ValidateParams(params[i]); err != nil {
      t.Errorf("unexpected error for valid params: %s, i = %d", err, i)
    }
  }
  params = genInvalidParams()
  for i := 0; i < len(params); i++ {
    if err := ValidateParams(params[i]); err == nil {
      t.Errorf("expect an error when params are invalid, i = %d", i)
    }
  }
}

func genInvalidParams() []*ecdsapb.EcdsaParams {
  return []*ecdsapb.EcdsaParams{
    // invalid encoding
    util.NewEcdsaParams(commonpb.HashType_SHA256,
                        commonpb.EllipticCurveType_NIST_P256,
                        ecdsapb.EcdsaSignatureEncoding_UNKNOWN_ENCODING),
    // invalid curve
    util.NewEcdsaParams(commonpb.HashType_SHA256,
                        commonpb.EllipticCurveType_UNKNOWN_CURVE,
                        ecdsapb.EcdsaSignatureEncoding_DER),
    // invalid hash: P256 and SHA-512
    util.NewEcdsaParams(commonpb.HashType_SHA512,
                        commonpb.EllipticCurveType_NIST_P256,
                        ecdsapb.EcdsaSignatureEncoding_DER),
    // invalid hash: P521 and SHA-256
    util.NewEcdsaParams(commonpb.HashType_SHA256,
                        commonpb.EllipticCurveType_NIST_P521,
                        ecdsapb.EcdsaSignatureEncoding_DER),
    // invalid hash: P384 and SHA-256
    util.NewEcdsaParams(commonpb.HashType_SHA256,
                        commonpb.EllipticCurveType_NIST_P384,
                        ecdsapb.EcdsaSignatureEncoding_DER),
  }
}

func genValidParams() []*ecdsapb.EcdsaParams {
  return []*ecdsapb.EcdsaParams{
    util.NewEcdsaParams(commonpb.HashType_SHA256,
                        commonpb.EllipticCurveType_NIST_P256,
                        ecdsapb.EcdsaSignatureEncoding_DER),
    util.NewEcdsaParams(commonpb.HashType_SHA512,
                        commonpb.EllipticCurveType_NIST_P384,
                        ecdsapb.EcdsaSignatureEncoding_DER),
    util.NewEcdsaParams(commonpb.HashType_SHA512,
                        commonpb.EllipticCurveType_NIST_P521,
                        ecdsapb.EcdsaSignatureEncoding_DER),
  }
}

func newRandomSignature() *EcdsaSignature {
  r := new(big.Int).SetBytes(random.GetRandomBytes(32))
  s := new(big.Int).SetBytes(random.GetRandomBytes(32))
  return NewSignature(r, s)
}