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

package insecurecleartextkeyset_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testing/fakemonitoring"
	"github.com/google/tink/go/testutil"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestInvalidInput(t *testing.T) {
	if _, err := insecurecleartextkeyset.Read(nil); err == nil {
		t.Error("insecurecleartextkeyset.Read should not accept nil as keyset")
	}
	if err := insecurecleartextkeyset.Write(nil, &keyset.MemReaderWriter{}); err == nil {
		t.Error("insecurecleartextkeyset.Write should not accept nil as keyset")
	}
	if err := insecurecleartextkeyset.Write(&keyset.Handle{}, nil); err == nil {
		t.Error("insecurecleartextkeyset.Write should not accept nil as writer")
	}
}

func TestHandleFromReader(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	manager := testutil.NewHMACKeysetManager()
	handle, err := manager.Handle()
	if handle == nil || err != nil {
		t.Fatalf("cannot get keyset handle: %v", err)
	}
	ks := insecurecleartextkeyset.KeysetMaterial(handle)
	parsedHandle, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		t.Fatalf("unexpected error reading keyset: %v", err)
	}
	parsedKs := insecurecleartextkeyset.KeysetMaterial(parsedHandle)
	if !proto.Equal(ks, parsedKs) {
		t.Errorf("parsed keyset (%s) doesn't match original keyset (%s)", parsedKs, ks)
	}
}

func TestLegacyKeysetHandle(t *testing.T) {
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf(" keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template()) err = %v, want nil", err)
	}
	ks := insecurecleartextkeyset.KeysetMaterial(handle)
	gotHandle1 := insecurecleartextkeyset.KeysetHandle(ks)
	if !cmp.Equal(gotHandle1.KeysetInfo(), handle.KeysetInfo(), protocmp.Transform()) {
		t.Errorf("gotHandle1.KeysetInfo() = %v, want %v", gotHandle1.KeysetInfo(), handle.KeysetInfo())
	}
	serializedKeyset, err := proto.Marshal(ks)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	gotHandle2, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(serializedKeyset)))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	if !cmp.Equal(gotHandle2.KeysetInfo(), handle.KeysetInfo(), protocmp.Transform()) {
		t.Errorf("gotHandle2.KeysetInfo() = %v, want %v", gotHandle2.KeysetInfo(), handle.KeysetInfo())
	}
}

func TestHandleFromReaderWithAnnotationsGetsMonitored(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf(" keyset.NewHandle(aead.AES256GCMKeyTemplate()) err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	wantAnnotations := map[string]string{"foo": "bar"}
	annotatedHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(wantAnnotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := aead.New(annotatedHandle)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	if _, err := p.Encrypt([]byte("some_data"), nil); err != nil {
		t.Fatalf("Encrypt() err = %v, want nil", err)
	}
	events := client.Events()
	gotAnnotations := events[0].Context.KeysetInfo.Annotations
	if !cmp.Equal(gotAnnotations, wantAnnotations) {
		t.Errorf("Annotations = %v, want %v", gotAnnotations, wantAnnotations)
	}
}

func TestHandleFromReaderWithAnnotationsTwiceFails(t *testing.T) {
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf(" keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	if _, err := insecurecleartextkeyset.Read(
		keyset.NewBinaryReader(buff),
		keyset.WithAnnotations(annotations),
		keyset.WithAnnotations(annotations)); err == nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = nil, want error")
	}
}

func TestHandleFromReaderWithoutAnnotationsDoesNotGetMonitored(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf(" keyset.NewHandle(aead.AES256GCMKeyTemplate()) err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	unannotatedHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := aead.New(unannotatedHandle)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	if _, err := p.Encrypt([]byte("some_data"), nil); err != nil {
		t.Fatalf("Encrypt() err = %v, want nil", err)
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
}

func TestWrite(t *testing.T) {
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	ks := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		t.Fatalf("unexpected error creating new KeysetHandle: %v", err)
	}
	exported := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(h, exported); err != nil {
		t.Fatalf("unexpected error writing keyset: %v", err)
	}
	if !proto.Equal(exported.Keyset, ks) {
		t.Errorf("exported keyset (%s) doesn't match original keyset (%s)", exported.Keyset, ks)
	}
}
