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

package mac_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestFactoryMultipleKeys(t *testing.T) {
	tagSize := uint32(16)
	keyset := testutil.NewTestHMACKeyset(tagSize, tinkpb.OutputPrefixType_TINK)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType != tinkpb.OutputPrefixType_TINK {
		t.Errorf("expect a tink key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}

	p, err := mac.New(keysetHandle)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	expectedPrefix, err := cryptofmt.OutputPrefix(primaryKey)
	if err != nil {
		t.Errorf("cryptofmt.OutputPrefix failed: %s", err)
	}

	if err := verifyMacPrimitive(p, p, expectedPrefix, tagSize); err != nil {
		t.Errorf("invalid primitive: %s", err)
	}

	// mac with a primary RAW key, verify with the keyset
	rawKey := keyset.Key[1]
	if rawKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a raw key")
	}
	keyset2 := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
	keysetHandle2, err := testkeyset.NewHandle(keyset2)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}

	p2, err := mac.New(keysetHandle2)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	if err := verifyMacPrimitive(p2, p, cryptofmt.RawPrefix, tagSize); err != nil {
		t.Errorf("invalid primitive: %s", err)
	}

	// mac with a random key not in the keyset, verify with the keyset should fail
	keyset2 = testutil.NewTestHMACKeyset(tagSize, tinkpb.OutputPrefixType_TINK)
	primaryKey = keyset2.Key[0]
	expectedPrefix, _ = cryptofmt.OutputPrefix(primaryKey)
	keysetHandle2, err = testkeyset.NewHandle(keyset2)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}

	p2, err = mac.New(keysetHandle2)
	if err != nil {
		t.Errorf("mac.New: cannot get primitive from keyset handle")
	}
	err = verifyMacPrimitive(p2, p, expectedPrefix, tagSize)
	if err == nil || !strings.Contains(err.Error(), "mac verification failed") {
		t.Errorf("Invalid MAC, shouldn't return valid")
	}
}

func TestFactoryRawKey(t *testing.T) {
	tagSize := uint32(16)
	keyset := testutil.NewTestHMACKeyset(tagSize, tinkpb.OutputPrefixType_RAW)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a raw key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}
	p, err := mac.New(keysetHandle)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	if err := verifyMacPrimitive(p, p, cryptofmt.RawPrefix, tagSize); err != nil {
		t.Errorf("invalid primitive: %s", err)
	}
}

func TestFactoryLegacyKey(t *testing.T) {
	tagSize := uint32(16)
	keyset := testutil.NewTestHMACKeyset(tagSize, tinkpb.OutputPrefixType_LEGACY)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType != tinkpb.OutputPrefixType_LEGACY {
		t.Errorf("expect a legacy key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}
	p, err := mac.New(keysetHandle)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	data := []byte("some data")
	tag, err := p.ComputeMAC(data)
	if err != nil {
		t.Errorf("mac computation failed: %s", err)
	}
	if err = p.VerifyMAC(tag, data); err != nil {
		t.Errorf("mac verification failed: %s", err)
	}
}

func TestFactoryLegacyFixedKeyFixedTag(t *testing.T) {
	tagSize := uint32(16)
	params := testutil.NewHMACParams(commonpb.HashType_SHA256, tagSize)
	keyValue := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	key := &hmacpb.HmacKey{
		Version:  0,
		Params:   params,
		KeyValue: keyValue,
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Errorf("failed serializing proto: %v", err)
	}
	keyData := &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	keyset := testutil.NewTestKeyset(keyData, tinkpb.OutputPrefixType_LEGACY)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType != tinkpb.OutputPrefixType_LEGACY {
		t.Errorf("expect a legacy key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}
	p, err := mac.New(keysetHandle)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	data := []byte("hello")
	tag := []byte{0, 0, 0, 0, 42, 64, 150, 12, 207, 250, 175, 32, 216, 164, 77, 69, 28, 29, 204, 235, 75}
	if err = p.VerifyMAC(tag, data); err != nil {
		t.Errorf("compatibleTag verification failed: %s", err)
	}
}

func verifyMacPrimitive(computePrimitive tink.MAC, verifyPrimitive tink.MAC,
	expectedPrefix string, tagSize uint32) error {
	data := []byte("hello")
	tag, err := computePrimitive.ComputeMAC(data)
	if err != nil {
		return fmt.Errorf("mac computation failed: %s", err)
	}
	prefixSize := len(expectedPrefix)
	if string(tag[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix")
	}
	if prefixSize+int(tagSize) != len(tag) {
		return fmt.Errorf("incorrect tag length")
	}
	if err = verifyPrimitive.VerifyMAC(tag, data); err != nil {
		return fmt.Errorf("mac verification failed: %s", err)
	}

	// Modify plaintext or tag and make sure VerifyMAC failed.
	var dataAndTag []byte
	dataAndTag = append(dataAndTag, data...)
	dataAndTag = append(dataAndTag, tag...)
	if err = verifyPrimitive.VerifyMAC(dataAndTag[len(data):], dataAndTag[:len(data)]); err != nil {
		return fmt.Errorf("mac verification failed: %s", err)
	}
	for i := 0; i < len(dataAndTag); i++ {
		tmp := dataAndTag[i]
		for j := 0; j < 8; j++ {
			dataAndTag[i] ^= 1 << uint8(j)
			if err = verifyPrimitive.VerifyMAC(dataAndTag[len(data):], dataAndTag[:len(data)]); err == nil {
				return fmt.Errorf("invalid tag or plaintext, mac should be invalid")
			}
			dataAndTag[i] = tmp
		}
	}
	return nil
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = mac.New(wrongKH)
	if err == nil {
		t.Fatal("calling New() with wrong *keyset.Handle should fail")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = mac.New(goodKH)
	if err != nil {
		t.Fatalf("calling New() with good *keyset.Handle failed: %s", err)
	}
}
