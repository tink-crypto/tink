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

package daead_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/internal/testing/stubkeymanager"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/monitoring"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testing/fakemonitoring"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestFactoryMultipleKeys(t *testing.T) {
	// encrypt with non-raw key.
	keyset := testutil.NewTestAESSIVKeyset(tinkpb.OutputPrefixType_TINK)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType == tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a non-raw key")
	}
	keysetHandle, _ := testkeyset.NewHandle(keyset)
	d, err := daead.New(keysetHandle)
	if err != nil {
		t.Errorf("daead.New failed: %s", err)
	}
	expectedPrefix, _ := cryptofmt.OutputPrefix(primaryKey)
	if err := validateDAEADFactoryCipher(d, d, expectedPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}

	// encrypt with a non-primary RAW key in keyset and decrypt with the keyset.
	{
		rawKey := keyset.Key[1]
		if rawKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
			t.Errorf("expect a raw key")
		}
		keyset2 := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
		keysetHandle2, _ := testkeyset.NewHandle(keyset2)
		d2, err := daead.New(keysetHandle2)
		if err != nil {
			t.Errorf("daead.New failed: %s", err)
		}
		if err := validateDAEADFactoryCipher(d2, d, cryptofmt.RawPrefix); err != nil {
			t.Errorf("invalid cipher: %s", err)
		}
	}

	// encrypt with a random key from a new keyset, decrypt with the original keyset should fail.
	{
		keyset2 := testutil.NewTestAESSIVKeyset(tinkpb.OutputPrefixType_TINK)
		newPK := keyset2.Key[0]
		if newPK.OutputPrefixType == tinkpb.OutputPrefixType_RAW {
			t.Errorf("expect a non-raw key")
		}
		keysetHandle2, _ := testkeyset.NewHandle(keyset2)
		d2, err := daead.New(keysetHandle2)
		if err != nil {
			t.Errorf("daead.New failed: %s", err)
		}
		expectedPrefix, _ = cryptofmt.OutputPrefix(newPK)
		err = validateDAEADFactoryCipher(d2, d, expectedPrefix)
		if err == nil || !strings.Contains(err.Error(), "decryption failed") {
			t.Errorf("expect decryption to fail with random key: %s", err)
		}
	}
}

func TestFactoryRawKeyAsPrimary(t *testing.T) {
	keyset := testutil.NewTestAESSIVKeyset(tinkpb.OutputPrefixType_RAW)
	if keyset.Key[0].OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("primary key is not a raw key")
	}
	keysetHandle, _ := testkeyset.NewHandle(keyset)

	d, err := daead.New(keysetHandle)
	if err != nil {
		t.Errorf("cannot get primitive from keyset handle: %s", err)
	}
	if err := validateDAEADFactoryCipher(d, d, cryptofmt.RawPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}
}

func validateDAEADFactoryCipher(encryptCipher, decryptCipher tink.DeterministicAEAD, expectedPrefix string) error {
	prefixSize := len(expectedPrefix)
	// regular plaintext.
	pt := random.GetRandomBytes(20)
	aad := random.GetRandomBytes(20)
	ct, err := encryptCipher.EncryptDeterministically(pt, aad)
	if err != nil {
		return fmt.Errorf("encryption failed with regular plaintext: %s", err)
	}
	decrypted, err := decryptCipher.DecryptDeterministically(ct, aad)
	if err != nil || !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed with regular plaintext: err: %s, pt: %s, decrypted: %s", err, pt, decrypted)
	}
	if string(ct[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix with regular plaintext")
	}

	// short plaintext.
	pt = random.GetRandomBytes(1)
	ct, err = encryptCipher.EncryptDeterministically(pt, aad)
	if err != nil {
		return fmt.Errorf("encryption failed with short plaintext: %s", err)
	}
	decrypted, err = decryptCipher.DecryptDeterministically(ct, aad)
	if err != nil || !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed with short plaintext: err: %s, pt: %s, decrypted: %s",
			err, pt, decrypted)
	}
	if string(ct[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix with short plaintext")
	}
	return nil
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = daead.New(wrongKH)
	if err == nil {
		t.Fatal("calling New() with wrong *keyset.Handle should fail")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = daead.New(goodKH)
	if err != nil {
		t.Fatalf("calling New() with good *keyset.Handle failed: %s", err)
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsLogsEncryptionDecryptionWithPrefix(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	pt := []byte("HELLO_WORLD")
	ct, err := p.EncryptDeterministically(pt, nil)
	if err != nil {
		t.Fatalf("p.EncryptDeterministically() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically(ct, nil); err != nil {
		t.Fatalf("p.DecryptDeterministically() err = %v, want nil", err)
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(
		annotations,
		kh.KeysetInfo().GetPrimaryKeyId(),
		[]*monitoring.Entry{
			{
				Status:    monitoring.Enabled,
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				KeyType:   "tink.AesSivKey",
				KeyPrefix: "TINK",
			},
		},
	)
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    mh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(pt),
			Context:  monitoring.NewContext("daead", "encrypt", wantKeysetInfo),
		},
		{
			KeyID: mh.KeysetInfo().GetPrimaryKeyId(),
			// Ciphertext was encrypted with a key that has a TINK output prefix. This adds a 5-byte prefix
			// to the ciphertext. This prefix is not included in `Log` call.
			NumBytes: len(ct) - cryptofmt.NonRawPrefixSize,
			Context:  monitoring.NewContext("daead", "decrypt", wantKeysetInfo),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsLogsEncryptionDecryptionWithoutPrefix(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	template := daead.AESSIVKeyTemplate()
	// There's currently not a raw template in the public API, but
	// we add a test by customizing the output prefix of an existing one.
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
	kh, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	data := []byte("hello_world")
	aad := []byte("_!")
	ct, err := p.EncryptDeterministically(data, aad)
	if err != nil {
		t.Fatalf("p.EncryptDeterministically() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically(ct, aad); err != nil {
		t.Fatalf("p.DecryptDeterministically() err = %v, want nil", err)
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(
		annotations,
		kh.KeysetInfo().GetPrimaryKeyId(),
		[]*monitoring.Entry{
			{
				Status:    monitoring.Enabled,
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				KeyType:   "tink.AesSivKey",
				KeyPrefix: "RAW",
			},
		},
	)
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("daead", "encrypt", wantKeysetInfo),
			KeyID:    wantKeysetInfo.PrimaryKeyID,
			NumBytes: len(data),
		},
		{
			Context:  monitoring.NewContext("daead", "decrypt", wantKeysetInfo),
			KeyID:    wantKeysetInfo.PrimaryKeyID,
			NumBytes: len(ct),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestFactoryWithMonitoringPrimitiveWithMultipleKeysLogsEncryptionDecryption(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	numKeys := 4
	keyIDs := make([]uint32, numKeys, numKeys)
	var err error
	for i := 0; i < numKeys; i++ {
		keyIDs[i], err = manager.Add(daead.AESSIVKeyTemplate())
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
	kh, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	data := []byte("YELLOW_ORANGE")
	ct, err := p.EncryptDeterministically(data, nil)
	if err != nil {
		t.Fatalf("p.EncryptDeterministically() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically(ct, nil); err != nil {
		t.Fatalf("p.DecryptDeterministically() err = %v, want nil", err)
	}
	failures := len(client.Failures())
	if failures != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", failures)
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(annotations, kh.KeysetInfo().GetPrimaryKeyId(), []*monitoring.Entry{
		{
			KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
			Status:    monitoring.Enabled,
			KeyType:   "tink.AesSivKey",
			KeyPrefix: "TINK",
		},
		{
			KeyID:     keyIDs[2],
			Status:    monitoring.Enabled,
			KeyType:   "tink.AesSivKey",
			KeyPrefix: "TINK",
		},
		{
			KeyID:     keyIDs[3],
			Status:    monitoring.Enabled,
			KeyType:   "tink.AesSivKey",
			KeyPrefix: "TINK",
		},
	})
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
			Context: monitoring.NewContext(
				"daead",
				"encrypt",
				wantKeysetInfo,
			),
		},
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct) - cryptofmt.NonRawPrefixSize,
			Context: monitoring.NewContext(
				"daead",
				"decrypt",
				wantKeysetInfo,
			),
		},
	}
	// sort by keyID to avoid non deterministic order.
	entryLessFunc := func(a, b *monitoring.Entry) bool {
		return a.KeyID < b.KeyID
	}
	if !cmp.Equal(got, want, cmpopts.SortSlices(entryLessFunc)) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsEncryptionFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{Name: ""}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	typeURL := "TestFactoryWithMonitoringPrimitiveEncryptionFailureIsLogged"
	km := &stubkeymanager.StubKeyManager{
		URL:  typeURL,
		Prim: &testutil.AlwaysFailingDeterministicAead{Error: fmt.Errorf("failed")},
		KeyData: &tinkpb.KeyData{
			TypeUrl:         typeURL,
			Value:           []byte("serialized_key"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
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
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	if _, err := p.EncryptDeterministically(nil, nil); err == nil {
		t.Fatalf("EncryptDeterministically() err = nil, want error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"daead",
				"encrypt",
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
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsDecryptionFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{Name: ""}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically([]byte("invalid_data"), nil); err == nil {
		t.Fatalf("DecryptDeterministically() err = nil, want error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"daead",
				"decrypt",
				monitoring.NewKeysetInfo(
					annotations,
					kh.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesSivKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestFactoryWithMonitoringMultiplePrimitivesLogOperations(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{Name: ""}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh1, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh1, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh1, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p1, err := daead.New(mh1)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	kh2, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(kh2, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	mh2, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p2, err := daead.New(mh2)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	d1 := []byte("YELLOW_ORANGE")
	if _, err := p1.EncryptDeterministically(d1, nil); err != nil {
		t.Fatalf("p1.EncryptDeterministically() err = %v, want nil", err)
	}
	d2 := []byte("ORANGE_BLUE")
	if _, err := p2.EncryptDeterministically(d2, nil); err != nil {
		t.Fatalf("p2.EncryptDeterministically() err = %v, want nil", err)
	}
	got := client.Events()
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    kh1.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(d1),
			Context: monitoring.NewContext(
				"daead",
				"encrypt",
				monitoring.NewKeysetInfo(
					annotations,
					kh1.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh1.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesSivKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
		{
			KeyID:    kh2.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(d2),
			Context: monitoring.NewContext(
				"daead",
				"encrypt",
				monitoring.NewKeysetInfo(
					annotations,
					kh2.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh2.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesSivKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryEncryptDecryptWithoutAnnotationsDoesNotMonitor(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	p, err := daead.New(kh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	data := []byte("hello_world")
	ct, err := p.EncryptDeterministically(data, nil)
	if err != nil {
		t.Fatalf("p.EncryptDeterministically() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically(ct, nil); err != nil {
		t.Fatalf("p.DecryptDeterministically() err = %v, want nil", err)
	}
	got := client.Events()
	if len(got) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(got))
	}
}
