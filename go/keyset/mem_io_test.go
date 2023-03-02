// Copyright 2023 Google LLC
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

package keyset_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestConvertProtoKeysetIntoHandleInTests(t *testing.T) {
	h, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	protoKeyset := testkeyset.KeysetMaterial(h)

	// In tests, this:
	wantHandle, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: protoKeyset})
	if err != nil {
		t.Fatal(err)
	}

	// can be replaced by this:
	gotHandle, err := testkeyset.NewHandle(protoKeyset)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := testkeyset.KeysetMaterial(gotHandle), testkeyset.KeysetMaterial(wantHandle); !proto.Equal(got, want) {
		t.Errorf("gotHandle contains %s, want %s", got, want)
	}
}

func TestConvertHandleKeysetIntoProtoKeysetInTests(t *testing.T) {
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}

	// In tests, this:
	writer := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(handle, writer); err != nil {
		t.Fatal(err)
	}
	wantKeyset := writer.Keyset

	// can be replaced by this:
	gotKeyset := testkeyset.KeysetMaterial(handle)

	if !proto.Equal(gotKeyset, wantKeyset) {
		t.Errorf("testkeyset.KeysetMaterial(handle) = %v, want %v", gotKeyset, wantKeyset)
	}
}

func TestConvertProtoKeysetIntoHandle(t *testing.T) {
	h, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	protoKeyset := testkeyset.KeysetMaterial(h)

	// This:
	wantHandle, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: protoKeyset})
	if err != nil {
		t.Fatal(err)
	}

	// can be replaced by this:
	serializedKeyset, err := proto.Marshal(protoKeyset)
	if err != nil {
		t.Fatal(err)
	}
	gotHandle, err := insecurecleartextkeyset.Read(
		keyset.NewBinaryReader(bytes.NewBuffer(serializedKeyset)))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := testkeyset.KeysetMaterial(gotHandle), testkeyset.KeysetMaterial(wantHandle); !proto.Equal(got, want) {
		t.Errorf("gotHandle contains %s, want %s", got, want)
	}
}

func TestConvertHandleKeysetIntoProtoKeyset(t *testing.T) {
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}

	// This:
	writer := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(handle, writer); err != nil {
		t.Fatal(err)
	}
	wantKeyset := writer.Keyset

	// can be replaced by this:
	gotKeyset := insecurecleartextkeyset.KeysetMaterial(handle)

	if !proto.Equal(gotKeyset, wantKeyset) {
		t.Errorf("insecurecleartextkeyset.KeysetMaterial(handle) = %v, want %v", gotKeyset, wantKeyset)
	}
}

func TestConvertHandleKeysetIntoSerializedKeyset(t *testing.T) {
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}

	// This:
	writer := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(handle, writer); err != nil {
		t.Fatal(err)
	}
	wantSerializedKeyset, err := proto.Marshal(writer.Keyset)
	if err != nil {
		t.Fatal(err)
	}

	// can be replaced by this:
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatal(err)
	}
	gotSerializedKeyset := buff.Bytes()

	// Since serialization may not be deterministic, we parse the keyset and compare the protos.
	wantKeyset := new(tinkpb.Keyset)
	err = proto.Unmarshal(wantSerializedKeyset, wantKeyset)
	if err != nil {
		t.Fatal(err)
	}
	gotKeyset := new(tinkpb.Keyset)
	err = proto.Unmarshal(gotSerializedKeyset, gotKeyset)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(gotKeyset, wantKeyset) {
		t.Errorf("gotKeyset = %v, want %v", gotKeyset, wantKeyset)
	}
}

func TestConvertPublicKeyProtoKeysetIntoHandle(t *testing.T) {
	privateHandle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	publicHandle, err := privateHandle.Public()
	if err != nil {
		t.Fatal(err)
	}
	protoPublicKeyset := testkeyset.KeysetMaterial(publicHandle)

	// This:
	wantHandle, err := keyset.ReadWithNoSecrets(&keyset.MemReaderWriter{Keyset: protoPublicKeyset})
	if err != nil {
		t.Fatal(err)
	}

	// can be replaced by this:
	serializedKeyset, err := proto.Marshal(protoPublicKeyset)
	if err != nil {
		t.Fatal(err)
	}
	gotHandle, err := keyset.ReadWithNoSecrets(
		keyset.NewBinaryReader(bytes.NewBuffer(serializedKeyset)))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := testkeyset.KeysetMaterial(gotHandle), testkeyset.KeysetMaterial(wantHandle); !proto.Equal(got, want) {
		t.Errorf("gotHandle contains %s, want %s", got, want)
	}
}

func TestConvertPublicKeysetHandleIntoProtoKeyset(t *testing.T) {
	privateHandle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	publicHandle, err := privateHandle.Public()
	if err != nil {
		t.Fatal(err)
	}

	// This:
	writer := &keyset.MemReaderWriter{}
	if err := publicHandle.WriteWithNoSecrets(writer); err != nil {
		t.Fatal(err)
	}
	wantKeyset := writer.Keyset

	// can be replaced by this:
	buff := &bytes.Buffer{}
	if err := publicHandle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatal(err)
	}
	serializedKeyset := buff.Bytes()
	gotKeyset := new(tinkpb.Keyset)
	err = proto.Unmarshal(serializedKeyset, gotKeyset)
	if err != nil {
		t.Fatal(err)
	}

	if !proto.Equal(gotKeyset, wantKeyset) {
		t.Errorf("gotKeyset = %v, want %v", gotKeyset, wantKeyset)
	}
}

func decryptKeyset(encrypted *tinkpb.EncryptedKeyset, keysetEncryptionAEAD tink.AEAD) (*tinkpb.Keyset, error) {
	decrypted, err := keysetEncryptionAEAD.Decrypt(encrypted.GetEncryptedKeyset(), nil)
	if err != nil {
		return nil, err
	}
	k := new(tinkpb.Keyset)
	err = proto.Unmarshal(decrypted, k)
	if err != nil {
		return nil, err
	}
	return k, err
}

func TestConvertHandleKeysetIntoProtoEncryptedKeyset(t *testing.T) {
	kekHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	keysetEncryptionAEAD, err := aead.New(kekHandle)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}

	// This:
	memWriter := &keyset.MemReaderWriter{}
	if err := handle.Write(memWriter, keysetEncryptionAEAD); err != nil {
		t.Fatal(err)
	}
	wantEncryptedKeyset := memWriter.EncryptedKeyset

	// can be replaced by this:
	buff := &bytes.Buffer{}
	if err := handle.Write(keyset.NewBinaryWriter(buff), keysetEncryptionAEAD); err != nil {
		t.Fatal(err)
	}
	serializedKeyset := buff.Bytes()
	gotEncryptedKeyset := new(tinkpb.EncryptedKeyset)
	err = proto.Unmarshal(serializedKeyset, gotEncryptedKeyset)
	if err != nil {
		t.Fatal(err)
	}

	wantKeyset, err := decryptKeyset(wantEncryptedKeyset, keysetEncryptionAEAD)
	if err != nil {
		t.Fatal(err)
	}
	gotKeyset, err := decryptKeyset(gotEncryptedKeyset, keysetEncryptionAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(gotKeyset, wantKeyset) {
		t.Errorf("gotKeyset = %v, want %v", gotKeyset, wantKeyset)
	}
}

func TestConvertProtoEncryptedKeysetIntoHandle(t *testing.T) {
	kekHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	keysetEncryptionAEAD, err := aead.New(kekHandle)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	buff := &bytes.Buffer{}
	if err := handle.Write(keyset.NewBinaryWriter(buff), keysetEncryptionAEAD); err != nil {
		t.Fatal(err)
	}
	encryptedKeyset := new(tinkpb.EncryptedKeyset)
	err = proto.Unmarshal(buff.Bytes(), encryptedKeyset)
	if err != nil {
		t.Fatal(err)
	}

	// This:
	memReader := &keyset.MemReaderWriter{
		EncryptedKeyset: encryptedKeyset,
	}
	wantHandle, err := keyset.Read(memReader, keysetEncryptionAEAD)
	if err != nil {
		t.Fatal(err)
	}

	// can be replaced by this:
	serializedKeyset, err := proto.Marshal(encryptedKeyset)
	if err != nil {
		t.Fatal(err)
	}
	gotHandle, err := keyset.Read(
		keyset.NewBinaryReader(bytes.NewBuffer(serializedKeyset)),
		keysetEncryptionAEAD)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := testkeyset.KeysetMaterial(gotHandle), testkeyset.KeysetMaterial(wantHandle); !proto.Equal(got, want) {
		t.Errorf("gotHandle contains %s, want %s", got, want)
	}
}
