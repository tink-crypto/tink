// Copyright 2018 Google LLC
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

package signature_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/internal/testing/stubkeymanager"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/monitoring"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testing/fakemonitoring"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestSignerVerifyFactory(t *testing.T) {
	tinkPriv, tinkPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	legacyPriv, legacyPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		tinkpb.OutputPrefixType_LEGACY,
		2)
	rawPriv, rawPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		tinkpb.OutputPrefixType_RAW,
		3)
	crunchyPriv, crunchyPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		tinkpb.OutputPrefixType_CRUNCHY,
		4)
	privKeys := []*tinkpb.Keyset_Key{tinkPriv, legacyPriv, rawPriv, crunchyPriv}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	privKeysetHandle, err := testkeyset.NewHandle(privKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle() err = %q, want nil", err)
	}
	pubKeys := []*tinkpb.Keyset_Key{tinkPub, legacyPub, rawPub, crunchyPub}
	pubKeyset := testutil.NewKeyset(pubKeys[0].KeyId, pubKeys)
	pubKeysetHandle, err := testkeyset.NewHandle(pubKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(pubKeyset) err = %v, want nil", err)
	}
	// sign some random data
	signer, err := signature.NewSigner(privKeysetHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privKeysetHandle) err = %v, want nil", err)
	}
	data := random.GetRandomBytes(1211)
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign(data) err = %v, want nil", err)
	}
	// verify with the same set of public keys should work
	verifier, err := signature.NewVerifier(pubKeysetHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(pubKeysetHandle) err = %v, want nil", err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Errorf("verifier.Verify(sig, data) = %v, want nil", err)
	}
	// verify with other key should fail
	_, otherPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	otherPubKeys := []*tinkpb.Keyset_Key{otherPub}
	otherPubKeyset := testutil.NewKeyset(otherPubKeys[0].KeyId, otherPubKeys)
	otherPubKeysetHandle, err := testkeyset.NewHandle(otherPubKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(otherPubKeyset) err = %v, want nil", err)
	}
	otherVerifier, err := signature.NewVerifier(otherPubKeysetHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(otherPubKeysetHandle) err = %v, want nil", err)
	}
	if err = otherVerifier.Verify(sig, data); err == nil {
		t.Error("otherVerifier.Verify(sig, data) = nil, want not nil")
	}
}

func TestPrimitiveFactoryFailsWhenKeysetHasNoPrimary(t *testing.T) {
	privateKey, _ := newECDSAKeysetKeypair(t, commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	privateKeysetWithoutPrimary := &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{privateKey},
	}
	privateHandleWithoutPrimary, err := testkeyset.NewHandle(privateKeysetWithoutPrimary)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(privateKeysetWithoutPrimary) err = %v, want nil", err)
	}
	publicHandleWithoutPrimary, err := privateHandleWithoutPrimary.Public()
	if err != nil {
		t.Fatalf("privateHandleWithoutPrimary.Public() err = %v, want nil", err)
	}

	if _, err = signature.NewSigner(privateHandleWithoutPrimary); err == nil {
		t.Errorf("signature.NewSigner(privateHandleWithoutPrimary) err = nil, want not nil")
	}

	if _, err = signature.NewVerifier(publicHandleWithoutPrimary); err == nil {
		t.Errorf("signature.NewVerifier(publicHandleWithoutPrimary) err = nil, want not nil")
	}
}

func newECDSAKeysetKeypair(t *testing.T, hashType commonpb.HashType, curve commonpb.EllipticCurveType, outputPrefixType tinkpb.OutputPrefixType, keyID uint32) (*tinkpb.Keyset_Key, *tinkpb.Keyset_Key) {
	t.Helper()
	key := testutil.NewRandomECDSAPrivateKey(hashType, curve)
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	keyData := testutil.NewKeyData(testutil.ECDSASignerTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	privKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefixType)

	serializedKey, err = proto.Marshal(key.PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	keyData = testutil.NewKeyData(testutil.ECDSAVerifierTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	pubKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefixType)
	return privKey, pubKey
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}

	_, err = signature.NewSigner(wrongKH)
	if err == nil {
		t.Error("signature.NewSigner(wrongKH) err = nil, want not nil")
	}

	_, err = signature.NewVerifier(wrongKH)
	if err == nil {
		t.Error("signature.NewVerifier(wrongKH) err = nil, want not nil")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}

	_, err = signature.NewSigner(goodKH)
	if err != nil {
		t.Fatalf("signature.NewSigner(goodKH) err = %v, want nil", err)
	}

	goodPublicKH, err := goodKH.Public()
	if err != nil {
		t.Fatalf("goodKH.Public() err = %v, want nil", err)
	}

	_, err = signature.NewVerifier(goodPublicKH)
	if err != nil {
		t.Errorf("signature.NewVerifier(goodPublicKH) err = %v, want nil", err)
	}
}

func TestPrimitiveFactorySignVerifyWithoutAnnotationsDoesNothing(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(signature.ED25519KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier() err = %v, want nil", err)
	}
	data := []byte("some_important_data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign() err = %v, want nil", err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Fatalf("verifier.Verify() err = %v, want nil", err)
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsLogSignVerify(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(signature.ED25519KeyTemplate())
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
	signer, err := signature.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner() err = %v, want nil", err)
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
	verifier, err := signature.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier() err = %v, want nil", err)
	}
	data := []byte("some_important_data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign() err = %v, want nil", err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Fatalf("verifier.Verify() err = %v, want nil", err)
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
	got := client.Events()
	wantVerifyKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: pubHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.Ed25519PublicKey",
				KeyPrefix: "TINK",
			},
		},
	}
	wantSignKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.Ed25519PrivateKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("public_key_sign", "sign", wantSignKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
		{
			Context:  monitoring.NewContext("public_key_verify", "verify", wantVerifyKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

type alwaysFailingSigner struct{}

func (a *alwaysFailingSigner) Sign(data []byte) ([]byte, error) { return nil, fmt.Errorf("failed") }

func TestPrimitiveFactoryMonitoringWithAnnotationsSignFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	typeURL := "TestPrimitiveFactoryMonitoringWithAnnotationsSignFailureIsLogged" + "PrivateKeyManager"
	km := &stubkeymanager.StubPrivateKeyManager{
		StubKeyManager: stubkeymanager.StubKeyManager{
			URL:  typeURL,
			Prim: &alwaysFailingSigner{},
			KeyData: &tinkpb.KeyData{
				TypeUrl:         typeURL,
				Value:           []byte("serialized_key"),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
		},
	}
	if err := registry.RegisterKeyManager(km); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}
	template := &tinkpb.KeyTemplate{
		TypeUrl:          typeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_LEGACY,
	}
	kh, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner() err = %v, want nil", err)
	}
	if _, err := signer.Sign([]byte("some_data")); err == nil {
		t.Fatalf("signer.Sign() err = nil, want error")
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"public_key_sign",
				"sign",
				monitoring.NewKeysetInfo(
					annotations,
					kh.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   typeURL,
							KeyPrefix: "LEGACY",
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

func TestPrimitiveFactoryMonitoringWithAnnotationsVerifyFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(signature.ED25519KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	annotations := map[string]string{"foo": "bar"}
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier() err = %v, want nil", err)
	}
	if err := verifier.Verify([]byte("some_invalid_signature"), []byte("some_invalid_data")); err == nil {
		t.Fatalf("verifier.Verify() err = nil, want error")
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"public_key_verify",
				"verify",
				monitoring.NewKeysetInfo(
					annotations,
					pubHandle.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.Ed25519PublicKey",
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

func TestVerifyWithLegacyKeyDoesNotHaveSideEffectOnMessage(t *testing.T) {
	privateKey, publicKey := newECDSAKeysetKeypair(t, commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		tinkpb.OutputPrefixType_LEGACY,
		2)
	privateKeyset := testutil.NewKeyset(privateKey.KeyId, []*tinkpb.Keyset_Key{privateKey})
	privateHandle, err := testkeyset.NewHandle(privateKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(privateHandle) err = %v, want nil", err)
	}
	publicKeyset := testutil.NewKeyset(publicKey.KeyId, []*tinkpb.Keyset_Key{publicKey})
	publicHandle, err := testkeyset.NewHandle(publicKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(publicKeyset) err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(privateHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privateHandle) err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(publicHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(publicHandle) err = %v, want nil", err)
	}

	data := []byte("data")
	message := data[:3] // Let message be a slice of data.

	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("signer.Sign(message) err = %v, want nil", err)
	}
	err = verifier.Verify(sig, message)
	if err != nil {
		t.Fatalf("verifier.Verify(sig, message) err = %v, want nil", err)
	}
	wantData := []byte("data")
	if !bytes.Equal(data, wantData) {
		t.Errorf("data = %q, want: %q", data, wantData)
	}
}
