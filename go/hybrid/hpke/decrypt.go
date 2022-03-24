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
///////////////////////////////////////////////////////////////////////////////

package hpke

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/tink"
	pb "github.com/google/tink/go/proto/hpke_go_proto"
)

// Decrypt for HPKE implements interface HybridDecrypt.
type Decrypt struct {
	recipientPrivKey   *pb.HpkePrivateKey
	kem                kem
	kdf                kdf
	aead               aead
	encapsulatedKeyLen int
}

var _ tink.HybridDecrypt = (*Decrypt)(nil)

// NewDecrypt constructs a Decrypt using HpkePrivateKey.
func NewDecrypt(recipientPrivKey *pb.HpkePrivateKey) (*Decrypt, error) {
	if recipientPrivKey.GetPrivateKey() == nil || len(recipientPrivKey.GetPrivateKey()) == 0 {
		return nil, errors.New("HpkePrivateKey.PrivateKey bytes are missing")
	}
	kem, kdf, aead, err := newPrimitivesFromProto(recipientPrivKey.GetPublicKey().GetParams())
	if err != nil {
		return nil, err
	}
	return &Decrypt{recipientPrivKey, kem, kdf, aead, kem.encapsulatedKeyLength()}, nil
}

// Decrypt decrypts ciphertext, verifying the integrity of contextInfo.
func (d *Decrypt) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	if len(ciphertext) < d.encapsulatedKeyLen {
		return nil, fmt.Errorf("ciphertext (size %d) is too short", len(ciphertext))
	}

	encapsulatedKey := ciphertext[:d.encapsulatedKeyLen]
	aeadCiphertext := ciphertext[d.encapsulatedKeyLen:]

	ctx, err := newRecipientContext(encapsulatedKey, d.recipientPrivKey, d.kem, d.kdf, d.aead, contextInfo)
	if err != nil {
		return nil, fmt.Errorf("newRecipientContext: %v", err)
	}

	return ctx.open(aeadCiphertext, emptyAssociatedData)
}
