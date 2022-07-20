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

package hybrid_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const eciesAEADHKDFPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"

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
		t.Fatalf("testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, primaryPtFmt, primaryDek, primarySalt) err = %v, want nil", err)
	}
	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	if err != nil {
		t.Fatalf("proto.Marshal(primaryPrivProto) err = %v, want nil", err)
	}

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(eciesAEADHKDFPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto, err := testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, rawPtFmt, rawDek, rawSalt)
	if err != nil {
		t.Fatalf("testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, rawPtFmt, rawDek, rawSalt) err = %v, want nil", err)
	}
	sRawPriv, err := proto.Marshal(rawPrivProto)
	if err != nil {
		t.Fatalf("proto.Marshal(rawPrivProto) err = %v, want nil", err)
	}
	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(eciesAEADHKDFPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 11, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{primaryPrivKey, rawPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err := testkeyset.NewHandle(privKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(privKeyset) err = %v, want nil", err)
	}

	khPub, err := khPriv.Public()
	if err != nil {
		t.Fatalf("khPriv.Public() err = %v, want nil", err)
	}

	e, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt(khPub) err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt(khPriv) err = %v, want nil", err)
	}

	for i := 0; i < 1000; i++ {
		pt := random.GetRandomBytes(20)
		ci := random.GetRandomBytes(20)
		ct, err := e.Encrypt(pt, ci)
		if err != nil {
			t.Fatalf("e.Encrypt(pt, ci) err = %v, want nil", err)
		}
		gotpt, err := d.Decrypt(ct, ci)
		if err != nil {
			t.Fatalf("d.Decrypt(ct, ci) err = %v, want nil", err)
		}
		if !bytes.Equal(pt, gotpt) {
			t.Errorf("got plaintext %q, want %q", gotpt, pt)
		}
	}
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}

	_, err = hybrid.NewHybridEncrypt(wrongKH)
	if err == nil {
		t.Error("hybrid.NewHybridEncrypt(wrongKH) err = nil, want not nil")
	}

	_, err = hybrid.NewHybridDecrypt(wrongKH)
	if err == nil {
		t.Error("hybrid.NewHybridDecrypt(wrongKH) err = nil, want not nil")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate()) err = %v, want nil", err)
	}

	goodPublicKH, err := goodKH.Public()
	if err != nil {
		t.Fatalf("goodKH.Public() err = %v, want nil", err)
	}
	_, err = hybrid.NewHybridEncrypt(goodPublicKH)
	if err != nil {
		t.Errorf("hybrid.NewHybridEncrypt(goodPublicKH) err = %v, want nil", err)
	}

	_, err = hybrid.NewHybridDecrypt(goodKH)
	if err != nil {
		t.Errorf("hybrid.NewHybridDecrypt(goodKH) err = %v, want nil", err)
	}
}

func TestPrimitiveFactoryFailsWhenKeysetHasNoPrimary(t *testing.T) {
	curve := commonpb.EllipticCurveType_NIST_P256
	hash := commonpb.HashType_SHA256
	format := commonpb.EcPointFormat_UNCOMPRESSED
	dek := aead.AES128CTRHMACSHA256KeyTemplate()
	salt := []byte("some salt")
	privProto, err := testutil.GenerateECIESAEADHKDFPrivateKey(curve, hash, format, dek, salt)
	if err != nil {
		t.Fatalf("testutil.GenerateECIESAEADHKDFPrivateKey(curve, hash, format, dek, salt) failed: %s", err)
	}
	serialized, err := proto.Marshal(privProto)
	if err != nil {
		t.Fatalf("proto.Marshal(privateProto) err = %v, want nil", err)
	}
	privKey := testutil.NewKey(
		testutil.NewKeyData(eciesAEADHKDFPrivateKeyTypeURL, serialized, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)
	privKeysetWithoutPrimary := &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{privKey},
	}
	privHandleWithoutPrimary, err := testkeyset.NewHandle(privKeysetWithoutPrimary)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(privKeysetWithoutPrimary) err = %v, want nil", err)
	}
	pubHandleWithoutPrimary, err := privHandleWithoutPrimary.Public()
	if err != nil {
		t.Fatalf("privateHandleWithoutPrimary.Public() err = %v, want nil", err)
	}

	if _, err = hybrid.NewHybridEncrypt(pubHandleWithoutPrimary); err == nil {
		t.Errorf("NewHybridEncrypt(pubHandleWithoutPrimary) err = nil, want not nil")
	}

	if _, err = hybrid.NewHybridDecrypt(privHandleWithoutPrimary); err == nil {
		t.Errorf("NewHybridDecrypt(privHandleWithoutPrimary) err = nil, want not nil")
	}
}
