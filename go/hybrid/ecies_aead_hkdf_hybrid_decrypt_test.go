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
	subtle "github.com/google/tink/go/subtle/hybrid"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestXxx(t *testing.T) {
}

func modifyDecrypt(t *testing.T, c string, k *tinkpb.KeyTemplate) {
	t.Helper()
	curve, err := subtle.GetCurve(c)
	if err != nil {
		t.Fatalf("error getting %s curve: %s ", c, err)
	}
	pvt, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		t.Fatalf("error generating ECDH key pair: %s", err)
	}
	salt := random.GetRandomBytes(8)
	pt := random.GetRandomBytes(4)
	context := random.GetRandomBytes(4)
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
	ct, err := e.Encrypt(pt, context)
	if err != nil {
		t.Fatalf("encryption error :%s", err)
	}
	dt, err := d.Decrypt(ct, context)
	if err != nil {
		t.Fatalf("decryption error :%s", err)
	}
	if !bytes.Equal(dt, pt) {
		t.Fatalf("decryption not inverse of encryption")
	}

	for _, g := range testutil.GenerateMutations(ct) {
		if _, err := d.Decrypt(g, context); err == nil {
			t.Fatalf("invalid cipher text should throw exception")
		}
	}
	for _, g := range testutil.GenerateMutations(context) {
		if _, err := d.Decrypt(ct, g); err == nil {
			t.Fatalf("invalid context should throw exception")
		}
	}
	mSalt := make([]byte, len(salt))

	for i := 0; i < len(salt); i++ {
		for j := 0; j < 8; j++ {
			copy(mSalt, salt)
			mSalt[i] ^= (1 << uint8(j))
			d, err = subtle.NewECIESAEADHKDFHybridDecrypt(pvt, mSalt, "SHA256", "UNCOMPRESSED", rDem)
			if err != nil {
				t.Fatalf("subtle.NewECIESAEADHKDFHybridDecrypt:%v", err)
			}
			if _, err := d.Decrypt(ct, context); err == nil {
				t.Fatalf("invalid salt should throw exception")
			}
		}
	}
}

func TestECAESCTRHMACSHA256Decrypt(t *testing.T) {
	modifyDecrypt(t, "NIST_P256", aead.AES256CTRHMACSHA256KeyTemplate())
	modifyDecrypt(t, "NIST_P384", aead.AES256CTRHMACSHA256KeyTemplate())
	modifyDecrypt(t, "NIST_P521", aead.AES256CTRHMACSHA256KeyTemplate())
	modifyDecrypt(t, "NIST_P224", aead.AES256CTRHMACSHA256KeyTemplate())

	modifyDecrypt(t, "NIST_P256", aead.AES128CTRHMACSHA256KeyTemplate())
	modifyDecrypt(t, "NIST_P384", aead.AES128CTRHMACSHA256KeyTemplate())
	modifyDecrypt(t, "NIST_P521", aead.AES128CTRHMACSHA256KeyTemplate())
	modifyDecrypt(t, "NIST_P224", aead.AES128CTRHMACSHA256KeyTemplate())
}

func TestECAES256GCMDecrypt(t *testing.T) {
	modifyDecrypt(t, "NIST_P256", aead.AES256GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P384", aead.AES256GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P521", aead.AES256GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P224", aead.AES256GCMKeyTemplate())

	modifyDecrypt(t, "NIST_P256", aead.AES128GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P384", aead.AES128GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P521", aead.AES128GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P224", aead.AES128GCMKeyTemplate())
}
