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
	"testing"

	pb "github.com/google/tink/go/proto/hpke_go_proto"
)

func TestNewKEM(t *testing.T) {
	kemID, err := kemIDFromProto(pb.HpkeKem_DHKEM_X25519_HKDF_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if kemID != x25519HKDFSHA256 {
		t.Errorf("kemID: got %d, want %d", kemID, x25519HKDFSHA256)
	}

	kem, err := newKEM(kemID)
	if err != nil {
		t.Fatal(err)
	}
	if kem.id() != x25519HKDFSHA256 {
		t.Errorf("id: got %d, want %d", kem.id(), x25519HKDFSHA256)
	}
}

func TestNewKEMUnsupportedID(t *testing.T) {
	if _, err := newKEM(0x0010 /*= DHKEM(P-256, HKDF-SHA256)*/); err == nil {
		t.Fatal("newKEM(unsupported ID): got success, want err")
	}
}

func TestKEMIDFromProtoUnsupportedID(t *testing.T) {
	if _, err := kemIDFromProto(pb.HpkeKem_KEM_UNKNOWN); err == nil {
		t.Fatal("kemIDFromProto(unsupported ID): got success, want err")
	}
}

func TestNewKDF(t *testing.T) {
	kdfID, err := kdfIDFromProto(pb.HpkeKdf_HKDF_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if kdfID != hkdfSHA256 {
		t.Errorf("kdfID: got %d, want %d", kdfID, hkdfSHA256)
	}

	kdf, err := newKDF(kdfID)
	if err != nil {
		t.Fatal(err)
	}
	if kdf.id() != hkdfSHA256 {
		t.Errorf("id: got %d, want %d", kdf.id(), hkdfSHA256)
	}
}

func TestNewKDFUnsupportedID(t *testing.T) {
	if _, err := newKDF(0x0002 /*= HKDF-SHA384*/); err == nil {
		t.Fatal("newKDF(unsupported ID): got success, want err")
	}
}

func TestKDFIDFromProtoUnsupportedID(t *testing.T) {
	if _, err := kdfIDFromProto(pb.HpkeKdf_KDF_UNKNOWN); err == nil {
		t.Fatal("kdfIDFromProto(unsupported ID): got success, want err")
	}
}

func TestNewAEADAES128GCM(t *testing.T) {
	aeadID, err := aeadIDFromProto(pb.HpkeAead_AES_128_GCM)
	if err != nil {
		t.Fatal(err)
	}
	if aeadID != aes128GCM {
		t.Errorf("aeadID: got %d, want %d", aeadID, aes128GCM)
	}

	aead, err := newAEAD(aeadID)
	if err != nil {
		t.Fatal(err)
	}
	if aead.id() != aes128GCM {
		t.Errorf("id: got %d, want %d", aead.id(), aes128GCM)
	}
}

func TestNewAEADAES256GCM(t *testing.T) {
	aeadID, err := aeadIDFromProto(pb.HpkeAead_AES_256_GCM)
	if err != nil {
		t.Fatal(err)
	}
	if aeadID != aes256GCM {
		t.Errorf("aeadID: got %d, want %d", aeadID, aes256GCM)
	}

	aead, err := newAEAD(aeadID)
	if err != nil {
		t.Fatal(err)
	}
	if aead.id() != aes256GCM {
		t.Errorf("id: got %d, want %d", aead.id(), aes256GCM)
	}
}

func TestNewAEADUnsupportedID(t *testing.T) {
	if _, err := newAEAD(0xFFFF /*= Export-only*/); err == nil {
		t.Fatal("newAEAD(unsupported ID): got success, want err")
	}
}

func TestAEADIDFromProtoUnsupportedID(t *testing.T) {
	if _, err := aeadIDFromProto(pb.HpkeAead_AEAD_UNKNOWN); err == nil {
		t.Fatal("aeadIDFromProto(unsupported ID): got success, want err")
	}
}

func TestNewPrimitivesFromProto(t *testing.T) {
	params := &pb.HpkeParams{
		Kem:  pb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		Kdf:  pb.HpkeKdf_HKDF_SHA256,
		Aead: pb.HpkeAead_AES_256_GCM,
	}
	kem, kdf, aead, err := newPrimitivesFromProto(params)
	if err != nil {
		t.Fatalf("newPrimitivesFromProto: %v", err)
	}

	if kem.id() != x25519HKDFSHA256 {
		t.Errorf("kem.id: got %d, want %d", kem.id(), x25519HKDFSHA256)
	}
	if kdf.id() != hkdfSHA256 {
		t.Errorf("kdf.id: got %d, want %d", kdf.id(), hkdfSHA256)
	}
	if aead.id() != aes256GCM {
		t.Errorf("aead.id: got %d, want %d", aead.id(), aes256GCM)
	}
}

func TestNewPrimitivesFromProtoUnsupportedID(t *testing.T) {
	tests := []struct {
		name   string
		params *pb.HpkeParams
	}{
		{
			"KEM",
			&pb.HpkeParams{
				Kem:  pb.HpkeKem_KEM_UNKNOWN,
				Kdf:  pb.HpkeKdf_HKDF_SHA256,
				Aead: pb.HpkeAead_AES_256_GCM,
			},
		},
		{"KDF",
			&pb.HpkeParams{
				Kem:  pb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				Kdf:  pb.HpkeKdf_KDF_UNKNOWN,
				Aead: pb.HpkeAead_AES_256_GCM,
			},
		},
		{"AEAD",
			&pb.HpkeParams{
				Kem:  pb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				Kdf:  pb.HpkeKdf_HKDF_SHA256,
				Aead: pb.HpkeAead_AEAD_UNKNOWN,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, err := newPrimitivesFromProto(test.params); err == nil {
				t.Error("newPrimitivesFromProto: got success, want err")
			}
		})
	}
}
