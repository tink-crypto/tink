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

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestHybridFactoryTest(t *testing.T) {
	c := commonpb.EllipticCurveType_NIST_P256
	ht := commonpb.HashType_SHA256
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	primaryDek := aead.AES128CTRHMACSHA256KeyTemplate()
	rawDek := aead.AES128CTRHMACSHA256KeyTemplate()
	primarySalt := []byte("some salt")
	rawSalt := []byte("other salt")

	primaryPrivProto, err := testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, primaryPtFmt, primaryDek, primarySalt)
	if err != nil {
		t.Error(err)
	}
	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	if err != nil {
		t.Error(err)
	}

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(eciesAEADHKDFPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto, err := testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, rawPtFmt, rawDek, rawSalt)
	if err != nil {
		t.Error(err)
	}
	sRawPriv, err := proto.Marshal(rawPrivProto)
	if err != nil {
		t.Error(err)
	}
	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(eciesAEADHKDFPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 11, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{primaryPrivKey, rawPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err := testkeyset.NewHandle(privKeyset)
	if err != nil {
		t.Error(err)
	}

	khPub, err := khPriv.Public()
	if err != nil {
		t.Error(err)
	}

	e, err := NewHybridEncrypt(khPub)
	if err != nil {
		t.Error(err)
	}
	d, err := NewHybridDecrypt(khPriv)
	if err != nil {
		t.Error(err)
	}

	for i := 0; i < 1000; i++ {
		pt := random.GetRandomBytes(20)
		ci := random.GetRandomBytes(20)
		ct, err := e.Encrypt(pt, ci)
		if err != nil {
			t.Error(err)
		}
		gotpt, err := d.Decrypt(ct, ci)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(pt, gotpt) {
			t.Error("expected pt:", pt, " not equal to decrypted pt:", gotpt)
		}
	}
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = NewHybridEncrypt(wrongKH)
	if err == nil {
		t.Fatal("calling NewHybridEncrypt() with wrong *keyset.Handle should fail")
	}

	_, err = NewHybridDecrypt(wrongKH)
	if err == nil {
		t.Fatal("calling NewHybridDecrypt() with wrong *keyset.Handle should fail")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(ECIESHKDFAES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	goodPublicKH, err := goodKH.Public()
	if err != nil {
		t.Fatalf("failed to get public *keyset.Handle: %s", err)
	}
	_, err = NewHybridEncrypt(goodPublicKH)
	if err != nil {
		t.Fatalf("calling NewHybridEncrypt() with good *keyset.Handle failed: %s", err)
	}

	_, err = NewHybridDecrypt(goodKH)
	if err != nil {
		t.Fatalf("calling NewHybridDecrypt() with good *keyset.Handle failed %s", err)
	}
}
