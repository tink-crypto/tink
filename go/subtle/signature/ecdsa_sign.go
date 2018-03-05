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

package signature

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"

	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/tink"
)

// EcdsaSign is an implementation of PublicKeySign for ECDSA.
// At the moment, the implementation only accepts DER encoding.
type EcdsaSign struct {
	privateKey *ecdsa.PrivateKey
	hashFunc   func() hash.Hash
	encoding   string
}

// Assert that ecdsaSign implements the PublicKeySign interface.
var _ tink.PublicKeySign = (*EcdsaSign)(nil)

// NewEcdsaSign creates a new instance of EcdsaSign.
func NewEcdsaSign(hashAlg string,
	curve string,
	encoding string,
	keyValue []byte) (*EcdsaSign, error) {
	privKey := new(ecdsa.PrivateKey)
	c := subtle.GetCurve(curve)
	privKey.PublicKey.Curve = c
	privKey.D = new(big.Int).SetBytes(keyValue)
	privKey.PublicKey.X, privKey.PublicKey.Y = c.ScalarBaseMult(keyValue)
	return NewEcdsaSignFromPrivateKey(hashAlg, encoding, privKey)
}

// NewEcdsaSignFromPrivateKey creates a new instance of EcdsaSign
func NewEcdsaSignFromPrivateKey(hashAlg string,
	encoding string,
	privateKey *ecdsa.PrivateKey) (*EcdsaSign, error) {
	if privateKey.Curve == nil {
		return nil, fmt.Errorf("ecdsa_sign: invalid curve")
	}
	curve := subtle.ConvertCurveName(privateKey.Curve.Params().Name)
	if err := ValidateEcdsaParams(hashAlg, curve, encoding); err != nil {
		return nil, fmt.Errorf("ecdsa_sign: %s", err)
	}
	hashFunc := subtle.GetHashFunc(hashAlg)
	return &EcdsaSign{
		privateKey: privateKey,
		hashFunc:   hashFunc,
		encoding:   encoding,
	}, nil
}

// Sign computes a signature for the given data.
func (e *EcdsaSign) Sign(data []byte) ([]byte, error) {
	hashed := subtle.ComputeHash(e.hashFunc, data)
	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, hashed)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_sign: signing failed: %s", err)
	}
	// format the signature
	sig := NewEcdsaSignature(r, s)
	ret, err := sig.EncodeEcdsaSignature(e.encoding)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_sign: signing failed: %s", err)
	}
	return ret, nil
}
