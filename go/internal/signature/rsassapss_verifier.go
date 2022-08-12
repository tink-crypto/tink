// Copyright 2022 Google LLC
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
	"github.com/google/tink/go/tink"
)

// RSA_SSA_PSS_Verifier is an implementation of Verifier for RSA-SSA-PSS.
type RSA_SSA_PSS_Verifier struct {
	publicKey  *rsa.PublicKey
	hashFunc   func() hash.Hash
	hashID     crypto.Hash
	saltLength int
}

var _ tink.Verifier = (*RSA_SSA_PSS_Verifier)(nil)

// New_RSA_SSA_PSS_Verifier creates a new instance of RSA_SSA_PSS_Verifier.
func New_RSA_SSA_PSS_Verifier(hashAlg string, saltLength int, pubKey *rsa.PublicKey) (*RSA_SSA_PSS_Verifier, error) {
	if err := validRSAPublicKey(pubKey); err != nil {
		return nil, err
	}
	hashFunc, hashID, err := rsaHashFunc(hashAlg)
	if err != nil {
		return nil, err
	}
	if saltLength < 0 {
		return nil, fmt.Errorf("invalid salt length")
	}
	return &RSA_SSA_PSS_Verifier{
		publicKey:  pubKey,
		hashFunc:   hashFunc,
		hashID:     hashID,
		saltLength: saltLength,
	}, nil
}

// Verify verifies whether the given signature is valid for the given data.
// It returns an error if the signature is not valid; nil otherwise.
func (v *RSA_SSA_PSS_Verifier) Verify(signature, data []byte) error {
	digest, err := subtle.ComputeHash(v.hashFunc, data)
	if err != nil {
		return err
	}
	return rsa.VerifyPSS(v.publicKey, v.hashID, digest, signature, &rsa.PSSOptions{SaltLength: v.saltLength})
}
