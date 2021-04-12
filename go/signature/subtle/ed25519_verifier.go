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
	"errors"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

var errInvalidED25519Signature = errors.New("ed25519: invalid signature")

// ED25519Verifier is an implementation of Verifier for ED25519.
// At the moment, the implementation only accepts signatures with strict DER encoding.
type ED25519Verifier struct {
	publicKey *ed25519.PublicKey
}

// NewED25519Verifier creates a new instance of ED25519Verifier.
func NewED25519Verifier(pub []byte) (*ED25519Verifier, error) {
	publicKey := ed25519.PublicKey(pub)
	return NewED25519VerifierFromPublicKey(&publicKey)
}

// NewED25519VerifierFromPublicKey creates a new instance of ED25519Verifier.
func NewED25519VerifierFromPublicKey(publicKey *ed25519.PublicKey) (*ED25519Verifier, error) {
	return &ED25519Verifier{
		publicKey: publicKey,
	}, nil
}

// Verify verifies whether the given signature is valid for the given data.
// It returns an error if the signature is not valid; nil otherwise.
func (e *ED25519Verifier) Verify(signature, data []byte) error {
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("the length of the signature is not %d", ed25519.SignatureSize)
	}
	if !ed25519.Verify(*e.publicKey, data, signature) {
		return errInvalidED25519Signature
	}
	return nil
}
