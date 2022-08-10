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

package signature

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"hash"

	"github.com/google/tink/go/subtle"
)

const (
	rsaMinModulusSizeInBits  = 2048
	rsaDefaultPublicExponent = 65537
)

// RSAValidModulusSizeInBits the size in bits for an RSA key.
func RSAValidModulusSizeInBits(m int) error {
	if m < rsaMinModulusSizeInBits {
		return fmt.Errorf("modulus size too small, must be >= %d", rsaMinModulusSizeInBits)
	}
	return nil
}

// RSAValidPublicExponent validates a public RSA exponent.
func RSAValidPublicExponent(e int) error {
	// crypto/rsa uses the following hardcoded public exponent value.
	if e != rsaDefaultPublicExponent {
		return fmt.Errorf("invalid public exponent")
	}
	return nil
}

// HashSafeForSignature checks whether a hash function is safe to use with digital signatures
// that require collision resistance.
func HashSafeForSignature(hashAlg string) error {
	switch hashAlg {
	case "SHA256", "SHA384", "SHA512":
		return nil
	default:
		return fmt.Errorf("hash function not safe for digital signatures: %q", hashAlg)
	}
}

func validRSAPublicKey(publicKey *rsa.PublicKey) error {
	if err := RSAValidModulusSizeInBits(publicKey.N.BitLen()); err != nil {
		return err
	}
	return RSAValidPublicExponent(publicKey.E)
}

func hashID(hashAlg string) (crypto.Hash, error) {
	switch hashAlg {
	case "SHA256":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("invalid hash function: %q", hashAlg)
	}
}

func rsaHashFunc(hashAlg string) (func() hash.Hash, crypto.Hash, error) {
	if err := HashSafeForSignature(hashAlg); err != nil {
		return nil, 0, err
	}
	hashFunc := subtle.GetHashFunc(hashAlg)
	if hashFunc == nil {
		return nil, 0, fmt.Errorf("invalid hash function: %q", hashAlg)
	}
	hashID, err := hashID(hashAlg)
	if err != nil {
		return nil, 0, err
	}
	return hashFunc, hashID, nil
}
