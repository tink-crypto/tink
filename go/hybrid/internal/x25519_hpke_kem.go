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
///////////////////////////////////////////////////////////////////////////////

package internal

import (
	"fmt"

	"github.com/google/tink/go/subtle"
)

// x25519HpkeKem is a Diffie-Hellman-based X25519 HPKE KEM variant that
// implements interface hpkeKem.
var (
	_ hpkeKem = (*x25519HpkeKem)(nil)

	generatePrivateKey      = subtle.GeneratePrivateKeyX25519
	publicFromPrivateX25519 = subtle.PublicFromPrivateX25519
)

type x25519HpkeKem struct {
	// HPKE KEM algorithm identifier.
	id     uint16
	macAlg string
}

// newX25519HpkeKem constructs a X25519 HPKE KEM using macAlg.
func newX25519HpkeKem(macAlg string) (*x25519HpkeKem, error) {
	if macAlg == sha256 {
		return &x25519HpkeKem{
			id:     x25519HkdfSha256,
			macAlg: macAlg,
		}, nil
	}
	return nil, fmt.Errorf("MAC algorithm %s is not supported", macAlg)
}

func (x *x25519HpkeKem) encapsulate(recipientPubKey []byte) (sharedSecret, senderPubKey []byte, err error) {
	senderPrivKey, err := generatePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	dh, err := subtle.ComputeSharedSecretX25519(senderPrivKey, recipientPubKey)
	if err != nil {
		return nil, nil, err
	}
	senderPubKey, err = publicFromPrivateX25519(senderPrivKey)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, err = x.deriveKEMSharedSecret(dh, senderPubKey, recipientPubKey)
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, senderPubKey, nil
}

func (x *x25519HpkeKem) decapsulate(encapsulatedKey, recipientPrivKey []byte) ([]byte, error) {
	dh, err := subtle.ComputeSharedSecretX25519(recipientPrivKey, encapsulatedKey)
	if err != nil {
		return nil, err
	}
	recipientPubKey, err := publicFromPrivateX25519(recipientPrivKey)
	if err != nil {
		return nil, err
	}
	return x.deriveKEMSharedSecret(dh, encapsulatedKey, recipientPubKey)
}

func (x *x25519HpkeKem) kemID() uint16 {
	return x.id
}

// deriveKEMSharedSecret returns a pseudorandom key obtained via HKDF SHA256.
func (x *x25519HpkeKem) deriveKEMSharedSecret(dh, senderPubKey, recipientPubKey []byte) ([]byte, error) {
	ctx := append(senderPubKey, recipientPubKey...)
	suiteID := kemSuiteID(x25519HkdfSha256)
	macLength, err := subtle.GetHashDigestSize(x.macAlg)
	if err != nil {
		return nil, err
	}
	info, err := labelInfo("shared_secret", ctx, suiteID, int(macLength))
	if err != nil {
		return nil, err
	}
	return subtle.ComputeHKDF(
		x.macAlg,
		labelIKM("eae_prk", dh, suiteID),
		/*salt=*/ nil,
		info,
		macLength)
}
