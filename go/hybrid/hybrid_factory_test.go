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

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/monitoring"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testing/fakemonitoring"
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

func TestPrimitiveFactoryMonitoringWithAnnotationsLogsEncryptAndDecryptWithPrefix(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	data := []byte("some_secret_piece_of_data")
	aad := []byte("some_non_secret_piece_of_data")
	ct, err := e.Encrypt(data, aad)
	if err != nil {
		t.Fatalf("e.Encrypt() err = %v, want nil", err)
	}
	if _, err := d.Decrypt(ct, aad); err != nil {
		t.Fatalf("d.Decrypt() err = %v, want nil", err)
	}
	got := client.Events()
	wantEncryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePublicKey",
				KeyPrefix: "TINK",
			},
		},
	}
	wantDecryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePrivateKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("hybrid_encrypt", "encrypt", wantEncryptKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
		{
			Context: monitoring.NewContext("hybrid_decrypt", "decrypt", wantDecryptKeysetInfo),
			KeyID:   privHandle.KeysetInfo().GetPrimaryKeyId(),
			// ciphertext was encrypted with a key that has a TINK output prefix. This adds a
			// 5-byte prefix to the ciphertext. This prefix is not included in the `Log` call.
			NumBytes: len(ct) - cryptofmt.NonRawPrefixSize,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsLogsEncryptAndDecryptWithoutPrefix(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Raw_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	data := []byte("some_secret_piece_of_data")
	aad := []byte("some_non_secret_piece_of_data")
	ct, err := e.Encrypt(data, aad)
	if err != nil {
		t.Fatalf("e.Encrypt() err = %v, want nil", err)
	}
	if _, err := d.Decrypt(ct, aad); err != nil {
		t.Fatalf("d.Decrypt() err = %v, want nil", err)
	}
	got := client.Events()
	wantEncryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePublicKey",
				KeyPrefix: "RAW",
			},
		},
	}
	wantDecryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePrivateKey",
				KeyPrefix: "RAW",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("hybrid_encrypt", "encrypt", wantEncryptKeysetInfo),
			KeyID:    pubHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
		{
			Context:  monitoring.NewContext("hybrid_decrypt", "decrypt", wantDecryptKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryWithMonitoringWithMultipleKeysLogsEncryptionDecryption(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	templates := []*tinkpb.KeyTemplate{
		hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template(),
		hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Raw_Key_Template(),
		hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template(),
		hybrid.ECIESHKDFAES128GCMKeyTemplate(),
	}
	keyIDs := make([]uint32, 4, 4)
	var err error
	for i, tm := range templates {
		keyIDs[i], err = manager.Add(tm)
		if err != nil {
			t.Fatalf("manager.Add() err = %v, want nil", err)
		}
	}
	if err := manager.SetPrimary(keyIDs[1]); err != nil {
		t.Fatalf("manager.SetPrimary(%d) err = %v, want nil", keyIDs[1], err)
	}
	if err := manager.Disable(keyIDs[0]); err != nil {
		t.Fatalf("manager.Disable(%d) err = %v, want nil", keyIDs[0], err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	data := []byte("some_secret_piece_of_data")
	aad := []byte("some_non_secret_piece_of_data")
	ct, err := e.Encrypt(data, aad)
	if err != nil {
		t.Fatalf("e.Encrypt() err = %v, want nil", err)
	}
	if _, err := d.Decrypt(ct, aad); err != nil {
		t.Fatalf("d.Decrypt() err = %v, want nil", err)
	}
	failures := len(client.Failures())
	if failures != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", failures)
	}
	got := client.Events()
	wantEncryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePublicKey",
				KeyPrefix: "RAW",
			},
			{
				KeyID:     keyIDs[2],
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePublicKey",
				KeyPrefix: "TINK",
			},
			{
				KeyID:     keyIDs[3],
				Status:    monitoring.Enabled,
				KeyType:   "tink.EciesAeadHkdfPublicKey",
				KeyPrefix: "TINK",
			},
		},
	}
	wantDecryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePrivateKey",
				KeyPrefix: "RAW",
			},
			{
				KeyID:     keyIDs[2],
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePrivateKey",
				KeyPrefix: "TINK",
			},
			{
				KeyID:     keyIDs[3],
				Status:    monitoring.Enabled,
				KeyType:   "tink.EciesAeadHkdfPrivateKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("hybrid_encrypt", "encrypt", wantEncryptKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
		{
			Context:  monitoring.NewContext("hybrid_decrypt", "decrypt", wantDecryptKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct),
		},
	}
	// sort by keyID to avoid non deterministic order.
	entryLessFunc := func(a, b *monitoring.Entry) bool {
		return a.KeyID < b.KeyID
	}
	if diff := cmp.Diff(want, got, cmpopts.SortSlices(entryLessFunc)); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsEncryptFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	buff.Reset()

	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}

	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("NewHybridDecrypt() err = %v, want nil", err)
	}

	ct, err := e.Encrypt([]byte("plaintext"), []byte("info"))
	if err != nil {
		t.Fatalf("Encrypt() err = nil, want non-nil")
	}
	if _, err := d.Decrypt(ct, []byte("wrong info")); err == nil {
		t.Fatalf("Decrypt() err = nil, want non-nil")
	}

	got := client.Failures()
	primaryKeyID := privHandle.KeysetInfo().GetPrimaryKeyId()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"hybrid_decrypt",
				"decrypt",
				monitoring.NewKeysetInfo(
					annotations,
					primaryKeyID,
					[]*monitoring.Entry{
						{
							KeyID:     primaryKeyID,
							Status:    monitoring.Enabled,
							KeyType:   "tink.HpkePrivateKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsDecryptFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	if _, err := e.Decrypt([]byte("invalid_data"), nil); err == nil {
		t.Fatalf("e.Decrypt() err = nil, want non-nil error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"hybrid_decrypt",
				"decrypt",
				monitoring.NewKeysetInfo(
					annotations,
					privHandle.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.HpkePrivateKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryEncryptDecryptWithoutAnnotationsDoesNotMonitor(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	data := []byte("some_secret_piece_of_data")
	aad := []byte("some_non_secret_piece_of_data")
	ct, err := e.Encrypt(data, aad)
	if err != nil {
		t.Fatalf("e.Encrypt() err = %v, want nil", err)
	}
	if _, err := d.Decrypt(ct, aad); err != nil {
		t.Fatalf("d.Decrypt() err = %v, want nil", err)
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
}

// Since the HybridEncrypt interface is a subset of the AEAD interface, verify
// that a HybridEncrypt primitive cannot be obtained from a keyset handle
// containing an AEAD key.
func TestEncryptFactoryFailsOnAEADHandle(t *testing.T) {
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle gives err = '%v', want nil", err)
	}
	pub, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public gives err = '%v', want nil", err)
	}
	manager := keyset.NewManagerFromHandle(pub)
	_, err = manager.Add(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add gives err = '%v', want nil", err)
	}
	mixedHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle gives err = '%v', want nil", err)
	}
	if _, err := hybrid.NewHybridEncrypt(mixedHandle); err == nil {
		t.Error("hybrid.NewHybridDecrypt err = nil, want err")
	}
}

// Similar to the above but for HybridDecrypt.
func TestDecryptFactoryFailsOnAEADHandle(t *testing.T) {
	manager := keyset.NewManager()
	id, err := manager.Add(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add gives err = '%v', want nil", err)
	}
	err = manager.SetPrimary(id)
	if err != nil {
		t.Fatalf("manager.SetPrimary gives err = '%v', want nil", err)
	}
	_, err = manager.Add(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("manager.Add gives err = '%v', want nil", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle gives err = '%v', want nil", err)
	}

	if _, err := hybrid.NewHybridDecrypt(handle); err == nil {
		t.Error("hybrid.NewHybridDecrypt err = nil, want err")
	}
}
