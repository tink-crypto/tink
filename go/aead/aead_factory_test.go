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

package aead_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"

	"github.com/google/tink/go/aead/subtle"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestFactoryMultipleKeys(t *testing.T) {
	// encrypt with non-raw key
	keyset := testutil.NewTestAESGCMKeyset(tinkpb.OutputPrefixType_TINK)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType == tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a non-raw key")
	}
	keysetHandle, _ := testkeyset.NewHandle(keyset)
	a, err := aead.New(keysetHandle)
	if err != nil {
		t.Errorf("aead.New failed: %s", err)
	}
	expectedPrefix, _ := cryptofmt.OutputPrefix(primaryKey)
	if err := validateAEADFactoryCipher(a, a, expectedPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}

	// encrypt with a non-primary RAW key and decrypt with the keyset
	rawKey := keyset.Key[1]
	if rawKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a raw key")
	}
	keyset2 := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
	keysetHandle2, _ := testkeyset.NewHandle(keyset2)
	a2, err := aead.New(keysetHandle2)
	if err != nil {
		t.Errorf("aead.New failed: %s", err)
	}
	if err := validateAEADFactoryCipher(a2, a, cryptofmt.RawPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}

	// encrypt with a random key not in the keyset, decrypt with the keyset should fail
	keyset2 = testutil.NewTestAESGCMKeyset(tinkpb.OutputPrefixType_TINK)
	primaryKey = keyset2.Key[0]
	expectedPrefix, _ = cryptofmt.OutputPrefix(primaryKey)
	keysetHandle2, _ = testkeyset.NewHandle(keyset2)
	a2, err = aead.New(keysetHandle2)
	if err != nil {
		t.Errorf("aead.New failed: %s", err)
	}
	err = validateAEADFactoryCipher(a2, a, expectedPrefix)
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("expect decryption to fail with random key: %s", err)
	}
}

func TestFactoryRawKeyAsPrimary(t *testing.T) {
	keyset := testutil.NewTestAESGCMKeyset(tinkpb.OutputPrefixType_RAW)
	if keyset.Key[0].OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("primary key is not a raw key")
	}
	keysetHandle, _ := testkeyset.NewHandle(keyset)

	a, err := aead.New(keysetHandle)
	if err != nil {
		t.Errorf("cannot get primitive from keyset handle: %s", err)
	}
	if err := validateAEADFactoryCipher(a, a, cryptofmt.RawPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}
}

func validateAEADFactoryCipher(encryptCipher tink.AEAD,
	decryptCipher tink.AEAD,
	expectedPrefix string) error {
	prefixSize := len(expectedPrefix)
	// regular plaintext
	pt := random.GetRandomBytes(20)
	ad := random.GetRandomBytes(20)
	ct, err := encryptCipher.Encrypt(pt, ad)
	if err != nil {
		return fmt.Errorf("encryption failed with regular plaintext: %s", err)
	}
	decrypted, err := decryptCipher.Decrypt(ct, ad)
	if err != nil || !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed with regular plaintext: err: %s, pt: %s, decrypted: %s",
			err, pt, decrypted)
	}
	if string(ct[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix with regular plaintext")
	}
	if prefixSize+len(pt)+subtle.AESGCMIVSize+subtle.AESGCMTagSize != len(ct) {
		return fmt.Errorf("lengths of plaintext and ciphertext don't match with regular plaintext")
	}

	// short plaintext
	pt = random.GetRandomBytes(1)
	ct, err = encryptCipher.Encrypt(pt, ad)
	if err != nil {
		return fmt.Errorf("encryption failed with short plaintext: %s", err)
	}
	decrypted, err = decryptCipher.Decrypt(ct, ad)
	if err != nil || !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed with short plaintext: err: %s, pt: %s, decrypted: %s",
			err, pt, decrypted)
	}
	if string(ct[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix with short plaintext")
	}
	if prefixSize+len(pt)+subtle.AESGCMIVSize+subtle.AESGCMTagSize != len(ct) {
		return fmt.Errorf("lengths of plaintext and ciphertext don't match with short plaintext")
	}
	return nil
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = aead.New(wrongKH)
	if err == nil {
		t.Fatalf("calling New() with wrong *keyset.Handle should fail")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = aead.New(goodKH)
	if err != nil {
		t.Fatalf("calling New() with good *keyset.Handle failed: %s", err)
	}
}
