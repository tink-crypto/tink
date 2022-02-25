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

package hpke

import (
	"fmt"

	"github.com/google/tink/go/subtle"
)

var (
	x25519KEMGeneratePrivateKey = subtle.GeneratePrivateKeyX25519
	x25519KEMPublicFromPrivate  = subtle.PublicFromPrivateX25519
)

// x25519KEM is a Diffie-Hellman-based X25519 HPKE KEM variant that implements
// interface kem.
type x25519KEM struct {
	// HPKE KEM algorithm identifier.
	kemID  uint16
	macAlg string
}

var _ kem = (*x25519KEM)(nil)

// newX25519KEM constructs a X25519 HPKE KEM using macAlg.
func newX25519KEM(macAlg string) (*x25519KEM, error) {
	if macAlg == sha256 {
		return &x25519KEM{kemID: x25519HKDFSHA256, macAlg: sha256}, nil
	}
	return nil, fmt.Errorf("MAC algorithm %s is not supported", macAlg)
}

func (x *x25519KEM) encapsulate(recipientPubKey []byte) (sharedSecret, senderPubKey []byte, err error) {
	senderPrivKey, err := x25519KEMGeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	dh, err := subtle.ComputeSharedSecretX25519(senderPrivKey, recipientPubKey)
	if err != nil {
		return nil, nil, err
	}
	senderPubKey, err = x25519KEMPublicFromPrivate(senderPrivKey)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, err = x.deriveKEMSharedSecret(dh, senderPubKey, recipientPubKey)
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, senderPubKey, nil
}

func (x *x25519KEM) decapsulate(encapsulatedKey, recipientPrivKey []byte) ([]byte, error) {
	dh, err := subtle.ComputeSharedSecretX25519(recipientPrivKey, encapsulatedKey)
	if err != nil {
		return nil, err
	}
	recipientPubKey, err := x25519KEMPublicFromPrivate(recipientPrivKey)
	if err != nil {
		return nil, err
	}
	return x.deriveKEMSharedSecret(dh, encapsulatedKey, recipientPubKey)
}

func (x *x25519KEM) id() uint16 {
	return x.kemID
}

func (x *x25519KEM) encapsulatedKeyLength() int {
	return 32
}

// deriveKEMSharedSecret returns a pseudorandom key obtained via HKDF SHA256.
func (x *x25519KEM) deriveKEMSharedSecret(dh, senderPubKey, recipientPubKey []byte) ([]byte, error) {
	ctx := make([]byte, len(senderPubKey))
	copy(ctx, senderPubKey)
	ctx = append(ctx, recipientPubKey...)

	suiteID := kemSuiteID(x25519HKDFSHA256)
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
