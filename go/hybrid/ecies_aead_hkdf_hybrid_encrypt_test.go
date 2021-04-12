// Copyright 2019 Google LLC
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

package hybrid

import (
	"bytes"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func basicMultipleEncrypts(t *testing.T, c string, k *tinkpb.KeyTemplate) {
	t.Helper()
	curve, err := subtle.GetCurve(c)
	if err != nil {
		t.Fatalf("error getting %s curve: %s ", c, err)
	}
	pvt, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		t.Fatalf("error generating ECDH key pair: %s", err)
	}
	salt := []byte("some salt")
	pt := random.GetRandomBytes(20)
	context := []byte("context info")
	rDem, err := newRegisterECIESAEADHKDFDemHelper(k)
	if err != nil {
		t.Fatalf("error generating a DEM helper :%s", err)
	}
	e, err := subtle.NewECIESAEADHKDFHybridEncrypt(&pvt.PublicKey, salt, "SHA256", "UNCOMPRESSED", rDem)
	if err != nil {
		t.Fatalf("error generating an encryption construct :%s", err)
	}
	d, err := subtle.NewECIESAEADHKDFHybridDecrypt(pvt, salt, "SHA256", "UNCOMPRESSED", rDem)
	if err != nil {
		t.Fatalf("error generating an decryption construct :%s", err)
	}
	cl := [][]byte{}
	for i := 0; i < 8; i++ {
		ct, err := e.Encrypt(pt, context)
		if err != nil {
			t.Fatalf("encryption error :%s", err)
		}
		for _, c := range cl {
			if bytes.Equal(ct, c) {
				t.Fatalf("encryption is not randomized")
			}
		}
		cl = append(cl, ct)
		dt, err := d.Decrypt(ct, context)
		if err != nil {
			t.Fatalf("decryption error :%s", err)
		}
		if !bytes.Equal(dt, pt) {
			t.Fatalf("decryption not inverse of encryption")
		}
	}
	if len(cl) != 8 {
		t.Errorf("randomized encryption check failed")
	}
}

func TestECAESCTRHMACSHA256Encrypt(t *testing.T) {
	basicMultipleEncrypts(t, "NIST_P256", aead.AES256CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES256CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES256CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES256CTRHMACSHA256KeyTemplate())

	basicMultipleEncrypts(t, "NIST_P256", aead.AES128CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES128CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES128CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES128CTRHMACSHA256KeyTemplate())
}

func TestECAES256GCMEncrypt(t *testing.T) {
	basicMultipleEncrypts(t, "NIST_P256", aead.AES256GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES256GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES256GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES256GCMKeyTemplate())

	basicMultipleEncrypts(t, "NIST_P256", aead.AES128GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES128GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES128GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES128GCMKeyTemplate())
}

func TestECAESSIVEncrypt(t *testing.T) {
	basicMultipleEncrypts(t, "NIST_P256", daead.AESSIVKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", daead.AESSIVKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", daead.AESSIVKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", daead.AESSIVKeyTemplate())
}
