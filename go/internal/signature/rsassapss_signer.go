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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"

	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/tink"
)

// RSA_SSA_PSS_Signer is an implementation of Signer for RSA-SSA-PSS.
type RSA_SSA_PSS_Signer struct {
	privateKey *rsa.PrivateKey
	hashFunc   func() hash.Hash
	hashID     crypto.Hash
	saltLength int
}

var _ tink.Signer = (*RSA_SSA_PSS_Signer)(nil)

// New_RSA_SSA_PSS_Signer creates a new instance of RSA_SSA_PSS_Signer.
func New_RSA_SSA_PSS_Signer(hashAlg string, saltLength int, privKey *rsa.PrivateKey) (*RSA_SSA_PSS_Signer, error) {
	if err := validRSAPublicKey(&privKey.PublicKey); err != nil {
		return nil, err
	}
	hashFunc, hashID, err := rsaHashFunc(hashAlg)
	if err != nil {
		return nil, err
	}
	if saltLength < 0 {
		return nil, fmt.Errorf("invalid salt length")
	}
	return &RSA_SSA_PSS_Signer{
		privateKey: privKey,
		hashFunc:   hashFunc,
		hashID:     hashID,
		saltLength: saltLength,
	}, nil
}

// Sign computes a signature for the given data.
func (s *RSA_SSA_PSS_Signer) Sign(data []byte) ([]byte, error) {
	digest, err := subtle.ComputeHash(s.hashFunc, data)
	if err != nil {
		return nil, err
	}
	return rsa.SignPSS(rand.Reader, s.privateKey, s.hashID, digest, &rsa.PSSOptions{SaltLength: s.saltLength})

}
