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

package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"hash"

	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/tink"
)

// RSA_SSA_PKCS1_Signer is an implementation of Signer for RSA-SSA-PKCS1.
type RSA_SSA_PKCS1_Signer struct {
	privateKey *rsa.PrivateKey
	hashFunc   func() hash.Hash
	hashID     crypto.Hash
}

var _ (tink.Signer) = (*RSA_SSA_PKCS1_Signer)(nil)

// New_RSA_SSA_PKCS1_Signer creates a new intance of RSA_SSA_PKCS1_Signer.
func New_RSA_SSA_PKCS1_Signer(hashAlg string, privKey *rsa.PrivateKey) (*RSA_SSA_PKCS1_Signer, error) {
	if err := validRSAPublicKey(privKey.Public().(*rsa.PublicKey)); err != nil {
		return nil, err
	}
	hashFunc, hashID, err := rsaHashFunc(hashAlg)
	if err != nil {
		return nil, err
	}
	return &RSA_SSA_PKCS1_Signer{
		privateKey: privKey,
		hashFunc:   hashFunc,
		hashID:     hashID,
	}, nil
}

// Sign computes a signature for the given data.
func (s *RSA_SSA_PKCS1_Signer) Sign(data []byte) ([]byte, error) {
	digest, err := subtle.ComputeHash(s.hashFunc, data)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, s.privateKey, s.hashID, digest)
}
