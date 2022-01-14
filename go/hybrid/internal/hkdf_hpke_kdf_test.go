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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/google/tink/go/subtle"
)

// TODO(b/201070904): Expand tests to use x25519HkdfSha256BaseModeTestVectors
// after it's in a separate package.

func internetDraftTestVector(t *testing.T) (vector, error) {
	t.Helper()

	// Test vector from HPKE I-D
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#appendix-A.1.1.
	v := struct {
		mode                                                                                                                uint8
		kemID, kdfID, aeadID                                                                                                uint16
		info, ikmE, pkEm, skEm, ikmR, pkRm, skRm, enc, sharedSecret, keyScheduleCtx, secret, key, baseNonce, exporterSecret string
	}{
		mode:           0,
		kemID:          32,
		kdfID:          1,
		aeadID:         1,
		info:           "4f6465206f6e2061204772656369616e2055726e",
		ikmE:           "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
		pkEm:           "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
		skEm:           "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
		ikmR:           "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
		pkRm:           "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
		skRm:           "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
		enc:            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
		sharedSecret:   "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
		keyScheduleCtx: "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449",
		secret:         "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397",
		key:            "4531685d41d65f03dc48f6b8302c05b0",
		baseNonce:      "56d890e5accaaf011cff4b7d",
		exporterSecret: "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
	}

	var info, senderPubKey, senderPrivKey, recipientPubKey, sharedSecret, keyScheduleCtx, secret, key, baseNonce []byte
	var err error
	if info, err = hex.DecodeString(v.info); err != nil {
		return vector{}, errors.New("hex.DecodeString(info) failed")
	}
	if senderPubKey, err = hex.DecodeString(v.pkEm); err != nil {
		return vector{}, errors.New("hex.DecodeString(pkEm) failed")
	}
	if senderPrivKey, err = hex.DecodeString(v.skEm); err != nil {
		return vector{}, errors.New("hex.DecodeString(skEm) failed")
	}
	if recipientPubKey, err = hex.DecodeString(v.pkRm); err != nil {
		return vector{}, errors.New("hex.DecodeString(pkRm) failed")
	}
	if sharedSecret, err = hex.DecodeString(v.sharedSecret); err != nil {
		return vector{}, errors.New("hex.DecodeString(sharedSecret) failed")
	}
	if keyScheduleCtx, err = hex.DecodeString(v.keyScheduleCtx); err != nil {
		return vector{}, errors.New("hex.DecodeString(keyScheduleCtx) failed")
	}
	if secret, err = hex.DecodeString(v.secret); err != nil {
		return vector{}, errors.New("hex.DecodeString(secret) failed")
	}
	if key, err = hex.DecodeString(v.key); err != nil {
		return vector{}, errors.New("hex.DecodeString(key) failed")
	}
	if baseNonce, err = hex.DecodeString(v.baseNonce); err != nil {
		return vector{}, errors.New("hex.DecodeString(baseNonce) failed")
	}

	return vector{
		mode:            v.mode,
		kemID:           v.kemID,
		kdfID:           v.kdfID,
		aeadID:          v.aeadID,
		info:            info,
		senderPubKey:    senderPubKey,
		senderPrivKey:   senderPrivKey,
		recipientPubKey: recipientPubKey,
		sharedSecret:    sharedSecret,
		keyScheduleCtx:  keyScheduleCtx,
		secret:          secret,
		key:             key,
		baseNonce:       baseNonce,
	}, nil
}

func TestHkdfHpkeKdfLabeledExtractWithInternetDraftTestVector(t *testing.T) {
	kdf, err := newHkdfHpkeKdf(sha256)
	if err != nil {
		t.Fatalf("newHkdfHpkeKdf(SHA256): got err %q, want success", err)
	}
	v, err := internetDraftTestVector(t)
	if err != nil {
		t.Fatal(err)
	}
	suiteID := hpkeSuiteID(v.kemID, v.kdfID, v.aeadID)

	// Base mode uses a default empty value for the pre-shared key (PSK), see
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-5.1-2.4.
	pskIDHash := kdf.labeledExtract(emptySalt, []byte{} /*=defaultPskId*/, "psk_id_hash", suiteID)
	infoHash := kdf.labeledExtract(emptySalt, v.info, "info_hash", suiteID)
	keyScheduleCtx := []byte{}
	keyScheduleCtx = append(keyScheduleCtx, v.mode)
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

func TestHkdfHpkeKdfLabeledExpand(t *testing.T) {
	kdf, err := newHkdfHpkeKdf(sha256)
	if err != nil {
		t.Fatalf("newHkdfHpkeKdf(SHA256): got err %q, want success", err)
	}
	v, err := internetDraftTestVector(t)
	if err != nil {
		t.Fatal(err)
	}
	suiteID := hpkeSuiteID(x25519HkdfSha256, hkdfSha256, aes128GCM)

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

func TestHkdfHpkeKdfLabeledExpandWithRFCTestVectors(t *testing.T) {
	kdf, err := newHkdfHpkeKdf(sha256)
	if err != nil {
		t.Fatalf("newHkdfHpkeKdf(SHA256): got err %q, want success", err)
	}
	suiteID := hpkeSuiteID(x25519HkdfSha256, hkdfSha256, aes128GCM)

	// Test vectors are defined at
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

func TestHkdfHpkeKdfExtractAndExpand(t *testing.T) {
	kdf, err := newHkdfHpkeKdf(sha256)
	if err != nil {
		t.Fatalf("newHkdfHpkeKdf(SHA256): got err %q, want success", err)
	}
	v, err := internetDraftTestVector(t)
	if err != nil {
		t.Fatal(err)
	}

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
				kemSuiteID(x25519HkdfSha256),
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

func TestHkdfHpkeKdfWithSha1Fails(t *testing.T) {
	if _, err := newHkdfHpkeKdf("SHA1"); err == nil {
		t.Fatalf("newHkdfHpkeKdf(SHA1): got success, want error")
	}
}
