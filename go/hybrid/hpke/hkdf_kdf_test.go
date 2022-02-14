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
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"github.com/google/tink/go/subtle"
)

// TODO(b/201070904): Write tests using baseModeX25519HKDFSHA256Vectors.
func TestHKDFKDFLabeledExtract(t *testing.T) {
	kdf, err := newKDF(hkdfSHA256)
	if err != nil {
		t.Fatalf("newKDF(hkdfSHA256): got err %q, want success", err)
	}
	id, v := internetDraftVector(t)
	suiteID := hpkeSuiteID(id.kemID, id.kdfID, id.aeadID)

	// Base mode uses a default empty value for the pre-shared key (PSK), see
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-5.1-2.4.
	pskIDHash := kdf.labeledExtract(emptySalt, []byte{} /*=defaultPSKID*/, "psk_id_hash", suiteID)
	infoHash := kdf.labeledExtract(emptySalt, v.info, "info_hash", suiteID)
	keyScheduleCtx := []byte{}
	keyScheduleCtx = append(keyScheduleCtx, id.mode)
	keyScheduleCtx = append(keyScheduleCtx, pskIDHash...)
	keyScheduleCtx = append(keyScheduleCtx, infoHash...)
	if !bytes.Equal(keyScheduleCtx, v.keyScheduleCtx) {
		t.Errorf("labeledExtract: got %x, want %x", keyScheduleCtx, v.keyScheduleCtx)
	}

	secret := kdf.labeledExtract(v.sharedSecret, []byte{} /*=defaultPSK*/, "secret", suiteID)
	if !bytes.Equal(secret, v.secret) {
		t.Errorf("labeledExtract: got %x, want %x", secret, v.secret)
	}
}

func TestHKDFKDFLabeledExpand(t *testing.T) {
	kdf, err := newKDF(hkdfSHA256)
	if err != nil {
		t.Fatalf("newKDF(hkdfSHA256): got err %q, want success", err)
	}
	id, v := internetDraftVector(t)
	suiteID := hpkeSuiteID(id.kemID, id.kdfID, id.aeadID)

	tests := []struct {
		infoLabel string
		length    int
		want      []byte
		wantErr   bool
	}{
		{"key", 16, v.key, false},
		{"base_nonce", 12, v.baseNonce, false},
		{"large_length", int(math.Pow(2, 16)), []byte{}, true},
	}

	for _, test := range tests {
		t.Run(test.infoLabel, func(t *testing.T) {
			got, err := kdf.labeledExpand(v.secret, v.keyScheduleCtx, test.infoLabel, suiteID, test.length)
			if test.wantErr {
				if err == nil {
					t.Error("labeledExpand: got success, want err")
				}
				return
			}

			if err != nil {
				t.Errorf("labeledExpand: got err %q, want success", err)
			}
			if !bytes.Equal(got, test.want) {
				t.Errorf("labeledExpand: got %x, want %x", got, test.want)
			}
		})
	}
}

func TestHKDFKDFLabeledExpandRFCVectors(t *testing.T) {
	kdf, err := newKDF(hkdfSHA256)
	if err != nil {
		t.Fatalf("newKDF(hkdfSHA256): got err %q, want success", err)
	}
	suiteID := hpkeSuiteID(x25519HKDFSHA256, hkdfSHA256, aes128GCM)

	// Vectors are defined at
	// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.
	var tests = []struct {
		name   string
		info   string
		prk    string
		length int
		want   string // Generated manually.
	}{
		{
			name:   "basic",
			info:   "f0f1f2f3f4f5f6f7f8f9",
			prk:    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			length: 42,
			want:   "2f1a8eb86971cd1850d04a1b98f9a63d52d56c5a4d5fcb68103e57c7a85a1df2c9be1346ae041007712d",
		},
		{
			name:   "longer inputs",
			info:   "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			prk:    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			length: 82,
			want:   "3961afd1985cb4d811e261b3568c44b88ae7e5d5909d33a5419e954eb245fe03fd3635769d88cec8adb709e900fa399e1a68bdb9d5c879e385845eeb99034fd232e30d1acc58f7fa37791fe0c433221b1fec",
		},
		{
			name:   "zero-length info",
			info:   "",
			prk:    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			length: 42,
			want:   "bdb2761a4f8504177b10ecc354f41153a3964435b9072d1f349c2993afbaa77a05ed426c384e195dba76",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := hex.DecodeString(test.info)
			if err != nil {
				t.Fatal("hex.DecodeString(info) failed")
			}
			prk, err := hex.DecodeString(test.prk)
			if err != nil {
				t.Fatal("hex.DecodeString(prk) failed")
			}
			want, err := hex.DecodeString(test.want)
			if err != nil {
				t.Fatal("hex.DecodeString(want) failed")
			}
			got, err := kdf.labeledExpand(prk, info, "info_label", suiteID, test.length)
			if err != nil {
				t.Errorf("labeledExpand: got err %q, want success", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("labeledExpand: got %x, want %x", got, want)
			}
		})
	}
}

func TestHKDFKDFExtractAndExpand(t *testing.T) {
	kdf, err := newKDF(hkdfSHA256)
	if err != nil {
		t.Fatalf("newKDF(hkdfSHA256): got err %q, want success", err)
	}
	_, v := internetDraftVector(t)

	dhSharedSecret, err := subtle.ComputeSharedSecretX25519(v.senderPrivKey, v.recipientPubKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecretX25519: got err %q, want success", err)
	}
	kemCtx := []byte{}
	kemCtx = append(kemCtx, v.senderPubKey...)
	kemCtx = append(kemCtx, v.recipientPubKey...)

	var tests = []struct {
		length  int
		want    []byte
		wantErr bool
	}{
		{32, v.sharedSecret, false},
		{int(math.Pow(2, 16)), nil, true},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%d", test.length), func(t *testing.T) {
			sharedSecret, err := kdf.extractAndExpand(
				emptySalt,
				dhSharedSecret,
				"eae_prk",
				kemCtx,
				"shared_secret",
				kemSuiteID(x25519HKDFSHA256),
				test.length)
			if test.wantErr {
				if err == nil {
					t.Error("extractAndExpand: got success, want err")
				}
				return
			}

			if err != nil {
				t.Errorf("extractAndExpand: got err %q, want success", err)
			}
			if !bytes.Equal(sharedSecret, v.sharedSecret) {
				t.Errorf("extractAndExpand: got %x, want %x", sharedSecret, v.sharedSecret)
			}
		})
	}
}
