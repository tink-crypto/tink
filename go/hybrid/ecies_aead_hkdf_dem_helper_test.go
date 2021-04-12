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
////////////////////////////////////////////////////////////////////////////////

package hybrid

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var (
	keyTemplates = map[*tinkpb.KeyTemplate]uint32{
		aead.AES256CTRHMACSHA256KeyTemplate(): 64,
		aead.AES128CTRHMACSHA256KeyTemplate(): 48,
		aead.AES256GCMKeyTemplate():           32,
		aead.AES128GCMKeyTemplate():           16,
		daead.AESSIVKeyTemplate():             64,
	}
	uTemplates = []*tinkpb.KeyTemplate{
		signature.ECDSAP256KeyTemplate(),
		mac.HMACSHA256Tag256KeyTemplate(),
		&tinkpb.KeyTemplate{TypeUrl: "some url", Value: []byte{0}},
		&tinkpb.KeyTemplate{TypeUrl: aesCTRHMACAEADTypeURL},
		&tinkpb.KeyTemplate{TypeUrl: aesGCMTypeURL},
		&tinkpb.KeyTemplate{TypeUrl: aesSIVTypeURL},
	}
)

func TestCipherKeySize(t *testing.T) {
	for c, l := range keyTemplates {
		rDem, err := newRegisterECIESAEADHKDFDemHelper(c)
		if err != nil {
			t.Fatalf("error generating a DEM helper :%s", err)
		}
		if rDem.GetSymmetricKeySize() != l {
			t.Errorf("incorrect key size %s template, got: %d, want: %d", c, rDem.GetSymmetricKeySize(), l)
		}
	}
}

func TestUnsupportedKeyTemplates(t *testing.T) {
	for _, l := range uTemplates {
		_, err := newRegisterECIESAEADHKDFDemHelper(l)
		if err == nil {
			t.Fatalf("unsupported key template %s should have generated error", l)
		}
	}
}

func TestAead(t *testing.T) {
	for c := range keyTemplates {
		pt := random.GetRandomBytes(20)
		ad := random.GetRandomBytes(20)
		rDem, err := newRegisterECIESAEADHKDFDemHelper(c)
		if err != nil {
			t.Fatalf("error generating a DEM helper :%s", err)
		}
		sk := random.GetRandomBytes(rDem.GetSymmetricKeySize())
		prim, err := rDem.GetAEADOrDAEAD(sk)
		if err != nil {
			t.Errorf("error getting AEAD primitive :%s", err)
		}
		var ct []byte
		switch a := prim.(type) {
		case tink.AEAD:
			ct, err = a.Encrypt(pt, ad)
		case tink.DeterministicAEAD:
			ct, err = a.EncryptDeterministically(pt, ad)
		}
		if err != nil {
			t.Errorf("error encrypting :%s", err)
		}

		var dt []byte
		switch a := prim.(type) {
		case tink.AEAD:
			dt, err = a.Decrypt(ct, ad)
		case tink.DeterministicAEAD:
			dt, err = a.DecryptDeterministically(ct, ad)
		}
		if err != nil {
			t.Errorf("error decrypting :%s", err)
		}
		if !bytes.Equal(dt, pt) {
			t.Errorf("decryption not inverse of encryption,\n want :%s,\n got: %s", hex.Dump(pt), hex.Dump(dt))
		}

		// shorter symmetric key
		sk = random.GetRandomBytes(rDem.GetSymmetricKeySize() - 1)
		if _, err = rDem.GetAEADOrDAEAD(sk); err == nil {
			t.Errorf("retrieving AEAD primitive should have failed")
		}

		// longer symmetric key
		sk = random.GetRandomBytes(rDem.GetSymmetricKeySize() + 1)
		if _, err = rDem.GetAEADOrDAEAD(sk); err == nil {
			t.Errorf("retrieving AEAD primitive should have failed")
		}

	}
}
