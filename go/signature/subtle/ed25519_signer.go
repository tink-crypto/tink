// Copyright 2020 Google LLC
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
	"golang.org/x/crypto/ed25519"
)

// ED25519Signer is an implementation of Signer for ED25519.
type ED25519Signer struct {
	privateKey *ed25519.PrivateKey
}

// NewED25519Signer creates a new instance of ED25519Signer.
func NewED25519Signer(keyValue []byte) (*ED25519Signer, error) {
	p := ed25519.NewKeyFromSeed(keyValue)
	return NewED25519SignerFromPrivateKey(&p)
}

// NewED25519SignerFromPrivateKey creates a new instance of ED25519Signer
func NewED25519SignerFromPrivateKey(privateKey *ed25519.PrivateKey) (*ED25519Signer, error) {
	return &ED25519Signer{
		privateKey: privateKey,
	}, nil
}

// Sign computes a signature for the given data.
func (e *ED25519Signer) Sign(data []byte) ([]byte, error) {
	r := ed25519.Sign(*e.privateKey, data)
	if len(r) != ed25519.SignatureSize {
		return nil, errInvalidED25519Signature
	}
	return r, nil
}
