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

import "testing"

func TestNewKEM(t *testing.T) {
	kem, err := newKEM(x25519HKDFSHA256)
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

func TestNewKDF(t *testing.T) {
	kdf, err := newKDF(hkdfSHA256)
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

func TestNewAEAD(t *testing.T) {
	aead, err := newAEAD(aes128GCM)
	if err != nil {
		t.Fatal(err)
	}
	if aead.id() != aes128GCM {
		t.Errorf("id: got %d, want %d", aead.id(), aes128GCM)
	}

	aead, err = newAEAD(aes256GCM)
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
