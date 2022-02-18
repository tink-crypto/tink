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
	"bytes"
	"math/big"
	"testing"

	"github.com/google/tink/go/subtle"
	pb "github.com/google/tink/go/proto/hpke_go_proto"
)

// TODO(b/201070904): Write tests using baseModeX25519HKDFSHA256Vectors.
func TestContextSender(t *testing.T) {
	id, vec := internetDraftVector(t)
	kem, err := newKEM(id.kemID)
	if err != nil {
		t.Fatalf("newKEM(%d): err %q", id.kemID, err)
	}
	x25519KEMGeneratePrivateKey = func() ([]byte, error) {
		return vec.senderPrivKey, nil
	}
	kdf, err := newKDF(id.kdfID)
	if err != nil {
		t.Fatalf("newKDF(%d): err %q", id.kdfID, err)
	}
	aead, err := newAEAD(id.aeadID)
	if err != nil {
		t.Fatalf("newAEAD(%d): err %q", id.aeadID, err)
	}

	recipientPubKey := &pb.HpkePublicKey{PublicKey: vec.recipientPubKey}
	senderCtx, err := newSenderContext(recipientPubKey, kem, kdf, aead, vec.info)
	if err != nil {
		t.Fatalf("newSenderContext: err %q", err)
	}

	for _, enc := range vec.consecutiveEncryptions {
		if got, want := senderCtx.sequenceNumber, enc.sequenceNumber; got.Cmp(want) != 0 {
			t.Fatalf("sequence number: got %s, want %s", got.String(), want.String())
		}
		ct, err := senderCtx.seal(enc.plaintext, enc.associatedData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ct, enc.ciphertext) {
			t.Errorf("ciphertext: got %x, want %x", ct, enc.ciphertext)
		}
	}

	for _, enc := range vec.otherEncryptions {
		senderCtx.sequenceNumber.Set(enc.sequenceNumber)
		ct, err := senderCtx.seal(enc.plaintext, enc.associatedData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ct, enc.ciphertext) {
			t.Errorf("ciphertext: got %x, want %x", ct, enc.ciphertext)
		}
	}

	x25519KEMGeneratePrivateKey = subtle.GeneratePrivateKeyX25519
}

func TestContextRecipient(t *testing.T) {
	id, vec := internetDraftVector(t)
	kem, err := newKEM(id.kemID)
	if err != nil {
		t.Fatalf("newKEM(%d): err %q", id.kemID, err)
	}
	x25519KEMGeneratePrivateKey = func() ([]byte, error) {
		return vec.senderPrivKey, nil
	}
	kdf, err := newKDF(id.kdfID)
	if err != nil {
		t.Fatalf("newKDF(%d): err %q", id.kdfID, err)
	}
	aead, err := newAEAD(id.aeadID)
	if err != nil {
		t.Fatalf("newAEAD(%d): err %q", id.aeadID, err)
	}

	recipientPrivKey := &pb.HpkePrivateKey{PrivateKey: vec.recipientPrivKey}
	recipientCtx, err := newRecipientContext(vec.encapsulatedKey, recipientPrivKey, kem, kdf, aead, vec.info)
	if err != nil {
		t.Fatalf("newRecipientContext: err %q", err)
	}

	for _, enc := range vec.consecutiveEncryptions {
		if got, want := recipientCtx.sequenceNumber, enc.sequenceNumber; got.Cmp(want) != 0 {
			t.Fatalf("sequence number: got %s, want %s", got.String(), want.String())
		}
		pt, err := recipientCtx.open(enc.ciphertext, enc.associatedData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, enc.plaintext) {
			t.Errorf("plaintext: got %x, want %x", pt, enc.plaintext)
		}
	}

	for _, enc := range vec.otherEncryptions {
		recipientCtx.sequenceNumber.Set(enc.sequenceNumber)
		pt, err := recipientCtx.open(enc.ciphertext, enc.associatedData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, enc.plaintext) {
			t.Errorf("plaintext: got %x, want %x", pt, enc.plaintext)
		}
	}

	x25519KEMGeneratePrivateKey = subtle.GeneratePrivateKeyX25519
}

func TestContextMaxSequenceNumber(t *testing.T) {
	got := maxSequenceNumber(12 /*=AESGCMIVSize*/)
	want, ok := new(big.Int).SetString("79228162514264337593543950335", 10) // (1 << (8*12)) - 1
	if !ok {
		t.Fatalf("SetString(\"79228162514264337593543950335\", 10): got err, want success")
	}
	if got.Cmp(want) != 0 {
		t.Errorf("maxSequenceNumber(12): got %s, want %s", got.String(), want.String())
	}
}

func TestComputeNonce(t *testing.T) {
	id, vec := internetDraftVector(t)
	kem, err := newKEM(id.kemID)
	if err != nil {
		t.Fatalf("newKEM(%d): err %q", id.kemID, err)
	}
	kdf, err := newKDF(id.kdfID)
	if err != nil {
		t.Fatalf("newKDF(%d): err %q", id.kdfID, err)
	}
	aead, err := newAEAD(id.aeadID)
	if err != nil {
		t.Fatalf("newAEAD(%d): err %q", id.aeadID, err)
	}

	recipientPrivKey := &pb.HpkePrivateKey{PrivateKey: vec.recipientPrivKey}
	ctx, err := newRecipientContext(vec.encapsulatedKey, recipientPrivKey, kem, kdf, aead, vec.info)
	if err != nil {
		t.Fatalf("newRecipientContext: err %q", err)
	}

	if !bytes.Equal(ctx.baseNonce, vec.baseNonce) {
		t.Fatalf("base nonce: got %x, want %x", ctx.baseNonce, vec.baseNonce)
	}

	for _, enc := range vec.consecutiveEncryptions {
		nonce, err := ctx.computeNonce()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(nonce, enc.nonce) {
			t.Errorf("computeNonce: got %x, want %x", nonce, enc.nonce)
		}
		if err := ctx.incrementSequenceNumber(); err != nil {
			t.Fatal(err)
		}
	}

	for _, enc := range vec.otherEncryptions {
		ctx.sequenceNumber.Set(enc.sequenceNumber)
		nonce, err := ctx.computeNonce()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(nonce, enc.nonce) {
			t.Errorf("computeNonce: got %x, want %x", nonce, enc.nonce)
		}
		if err := ctx.incrementSequenceNumber(); err != nil {
			t.Fatal(err)
		}
	}
}
