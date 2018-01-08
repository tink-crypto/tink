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
	"crypto/ecdsa"
	"fmt"
	"github.com/google/tink/go/subtle/subtleutil"
	"github.com/google/tink/go/tink/primitives"
	"hash"
	"math/big"
)

var errInvalidSignature = fmt.Errorf("ecdsa_verify: invalid signature")

// ecdsaVerify is an implementation of PublicKeyVerify for ECDSA.
// At the moment, the implementation only accepts signatures with strict DER encoding.
type EcdsaVerify struct {
	publicKey *ecdsa.PublicKey
	hashFunc  func() hash.Hash
	encoding  string
}

// Assert that EcdsaVerify implements the PublicKeyVerify interface.
var _ tink.PublicKeyVerify = (*EcdsaVerify)(nil)

// NewEcdsaVerify creates a new instance of EcdsaVerify.
func NewEcdsaVerify(hashAlg string,
	curve string,
	encoding string,
	x []byte,
	y []byte) (*EcdsaVerify, error) {
	publicKey := &ecdsa.PublicKey{
		Curve: subtleutil.GetCurve(curve),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	return NewEcdsaVerifyFromPublicKey(hashAlg, encoding, publicKey)
}

// NewEcdsaVerifyFromPublicKey creates a new instance of EcdsaVerify.
func NewEcdsaVerifyFromPublicKey(hashAlg string, encoding string,
	publicKey *ecdsa.PublicKey) (*EcdsaVerify, error) {
	if publicKey.Curve == nil {
		return nil, fmt.Errorf("ecdsa_verify: invalid curve")
	}
	curve := subtleutil.ConvertCurveName(publicKey.Curve.Params().Name)
	if err := ValidateParams(hashAlg, curve, encoding); err != nil {
		return nil, fmt.Errorf("ecdsa_verify: %s", err)
	}
	hashFunc := subtleutil.GetHashFunc(hashAlg)
	return &EcdsaVerify{
		publicKey: publicKey,
		hashFunc:  hashFunc,
		encoding:  encoding,
	}, nil
}

// Verify verifies whether the given signature is valid for the given data.
// It returns an error if the signature is not valid; nil otherwise.
func (e *EcdsaVerify) Verify(signatureBytes []byte, data []byte) error {
	signature, err := DecodeSignature(signatureBytes, e.encoding)
	if err != nil {
		return errInvalidSignature
	}
	hashed := subtleutil.ComputeHash(e.hashFunc, data)
	valid := ecdsa.Verify(e.publicKey, hashed, signature.R, signature.S)
	if valid {
		return nil
	}
	return errInvalidSignature
}
