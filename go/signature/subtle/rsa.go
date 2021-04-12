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

package subtle

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
)

var (
	errInvalidRSAPublicKeyData  = errors.New("invalid RSA public key data")
	errInvalidRSAPrivateKeyData = errors.New("invalid RSA private key data")
)

// GenerateRSAKey generates an RSA key with the given modulus size and public
// exponent.
//
// Note: The public exponent is hardcoded by the underlying crypto/rsa
// implementation. Other Tink implementations allow for the value to be specified
// so we accept it as an argument here solely to validate that the desired
// value is compatible.
func GenerateRSAKey(modulusSize, publicExponent int) (*rsa.PrivateKey, error) {
	if err := validModulusSize(modulusSize); err != nil {
		return nil, err
	}
	if err := validPublicExponent(publicExponent); err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, modulusSize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// RSAPublicKeyData contains the raw data that makes up an RSA public key.
//
// This facilitates creating instances of rsa.PublicKey from serialized
// key material.
type RSAPublicKeyData struct {
	E int
	N *big.Int
}

// Validate verifies that the parameters contain valid values.
func (r *RSAPublicKeyData) Validate() error {
	if err := validModulus(r.N); err != nil {
		return fmt.Errorf("%v: %v", errInvalidRSAPublicKeyData, err)
	}
	if err := validPublicExponent(r.E); err != nil {
		return fmt.Errorf("%v: %v", errInvalidRSAPublicKeyData, err)
	}
	return nil
}

// CreateKey creates an rsa.PublicKey.
func (r *RSAPublicKeyData) CreateKey() (*rsa.PublicKey, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}

	return &rsa.PublicKey{
		N: r.N,
		E: r.E,
	}, nil
}

// RSAPrivateKeyData contains the raw data that makes up an RSA private key.
//
// This facilitates creating instances of rsa.PrivateKey from serialized
// key material.
type RSAPrivateKeyData struct {
	D             *big.Int
	P             *big.Int
	Q             *big.Int
	Dp            *big.Int
	Dq            *big.Int
	Qinv          *big.Int
	PublicKeyData *RSAPublicKeyData
}

// Validate verifies that the populated data is valid.
func (r *RSAPrivateKeyData) Validate() error {
	_, err := r.CreateKey()
	return err
}

// CreateKey creates an rsa.PrivateKey.
func (r *RSAPrivateKeyData) CreateKey() (*rsa.PrivateKey, error) {
	if r.PublicKeyData == nil {
		return nil, errInvalidRSAPublicKeyData
	}
	pubKey, err := r.PublicKeyData.CreateKey()
	if err != nil {
		return nil, fmt.Errorf("%v: %v", errInvalidRSAPrivateKeyData, err)
	}
	privKey := &rsa.PrivateKey{
		PublicKey: *pubKey,
		D:         r.D,
		Primes:    []*big.Int{r.P, r.Q},
		Precomputed: rsa.PrecomputedValues{
			Dp:   r.Dp,
			Dq:   r.Dq,
			Qinv: r.Qinv,
		},
	}
	if err := privKey.Validate(); err != nil {
		return nil, fmt.Errorf("%v: %v", errInvalidRSAPrivateKeyData, err)
	}
	return privKey, nil
}

func validModulusSize(m int) error {
	if m < 2048 {
		return errors.New("modulus size too small, must be >= 2048")
	}
	return nil
}

func validModulus(m *big.Int) error {
	if validModulusSize(m.BitLen()) != nil {
		return errors.New("invlaid modulus")
	}
	return nil
}

func validPublicExponent(e int) error {
	// crypto/rsa uses the following hardcoded public exponent value.
	if e != 65537 {
		return errors.New("invalid public exponent")
	}
	return nil
}
