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

package hpke

import (
	"errors"
	"fmt"
	"math/big"

	pb "github.com/google/tink/go/proto/hpke_go_proto"
)

type context struct {
	aead              aead
	maxSequenceNumber *big.Int
	sequenceNumber    *big.Int
	key               []byte
	baseNonce         []byte
	encapsulatedKey   []byte
}

// newSenderContext creates the HPKE sender context as per KeySchedule()
// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-10.
func newSenderContext(recipientPubKey *pb.HpkePublicKey, kem kem, kdf kdf, aead aead, info []byte) (*context, error) {
	if recipientPubKey.GetPublicKey() == nil {
		return nil, errors.New("HpkePublicKey has an empty PublicKey")
	}
	sharedSecret, encapsulatedKey, err := kem.encapsulate(recipientPubKey.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("encapsulate: %v", err)
	}
	return createContext(encapsulatedKey, sharedSecret, kem, kdf, aead, info)
}

// newRecipientContext creates the HPKE recipient context as per KeySchedule()
// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-10.
func newRecipientContext(encapsulatedKey []byte, recipientPrivKey *pb.HpkePrivateKey, kem kem, kdf kdf, aead aead, info []byte) (*context, error) {
	if recipientPrivKey.GetPrivateKey() == nil {
		return nil, errors.New("HpkePrivateKey has an empty PrivateKey")
	}
	sharedSecret, err := kem.decapsulate(encapsulatedKey, recipientPrivKey.GetPrivateKey())
	if err != nil {
		return nil, fmt.Errorf("decapsulate: %v", err)
	}
	return createContext(encapsulatedKey, sharedSecret, kem, kdf, aead, info)
}

func createContext(encapsulatedKey []byte, sharedSecret []byte, kem kem, kdf kdf, aead aead, info []byte) (*context, error) {
	suiteID := hpkeSuiteID(kem.id(), kdf.id(), aead.id())
	// In base mode, both the pre-shared key (default_psk) and pre-shared key ID
	// (default_psk_id) are empty strings, see
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.1-4.
	pskIDHash := kdf.labeledExtract(emptySalt, emptyIKM /*= default PSK ID*/, "psk_id_hash", suiteID)
	infoHash := kdf.labeledExtract(emptySalt, info, "info_hash", suiteID)
	keyScheduleCtx := keyScheduleContext(baseMode, pskIDHash, infoHash)
	secret := kdf.labeledExtract(sharedSecret, emptyIKM /*= default PSK*/, "secret", suiteID)

	key, err := kdf.labeledExpand(secret, keyScheduleCtx, "key", suiteID, aead.keyLength())
	if err != nil {
		return nil, fmt.Errorf("labeledExpand of key: %v", err)
	}
	baseNonce, err := kdf.labeledExpand(secret, keyScheduleCtx, "base_nonce", suiteID, aead.nonceLength())
	if err != nil {
		return nil, fmt.Errorf("labeledExpand of base nonce: %v", err)
	}

	return &context{
		aead:              aead,
		maxSequenceNumber: maxSequenceNumber(aead.nonceLength()),
		sequenceNumber:    big.NewInt(0),
		key:               key,
		baseNonce:         baseNonce,
		encapsulatedKey:   encapsulatedKey,
	}, nil
}

// maxSequenceNumber returns the maximum sequence number indicating that the
// message limit is reached, calculated as per
// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-11.
func maxSequenceNumber(nonceLength int) *big.Int {
	res := new(big.Int)
	one := big.NewInt(1)
	res.Lsh(one, uint(8*nonceLength)).Sub(res, one)
	return res
}

func (c *context) incrementSequenceNumber() error {
	c.sequenceNumber.Add(c.sequenceNumber, big.NewInt(1))
	if c.sequenceNumber.Cmp(c.maxSequenceNumber) > 0 {
		return errors.New("message limit reached")
	}
	return nil
}

// computeNonce computes the nonce as per
// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-12.
func (c *context) computeNonce() ([]byte, error) {
	nonce := make([]byte, len(c.baseNonce))

	// Write the big-endian c.sequenceNumber value at the end of nonce.
	sequenceNumber := c.sequenceNumber.Bytes()
	index := len(nonce) - len(sequenceNumber)
	if index < 0 {
		return nil, fmt.Errorf("sequence number length (%d) is larger than nonce length (%d)", len(sequenceNumber), len(nonce))
	}
	copy(nonce[index:], sequenceNumber)

	// nonce XOR c.baseNonce.
	for i, b := range c.baseNonce {
		nonce[i] ^= b
	}

	return nonce, nil
}

// seal allows the sender's context to encrypt plaintext with associatedData,
// defined as ContextS.Seal in
// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-7.
func (c *context) seal(plaintext, associatedData []byte) ([]byte, error) {
	nonce, err := c.computeNonce()
	if err != nil {
		return nil, fmt.Errorf("computeNonce: %v", err)
	}
	ciphertext, err := c.aead.seal(c.key, nonce, plaintext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("seal: %v", err)
	}
	if err := c.incrementSequenceNumber(); err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// open allows the receiver's context to decrypt ciphertext with
// associatedData, defined as ContextR.Open in
// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-9.
func (c *context) open(ciphertext, associatedData []byte) ([]byte, error) {
	nonce, err := c.computeNonce()
	if err != nil {
		return nil, fmt.Errorf("computeNonce: %v", err)
	}
	plaintext, err := c.aead.open(c.key, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("open: %v", err)
	}
	if err := c.incrementSequenceNumber(); err != nil {
		return nil, err
	}
	return plaintext, nil
}
