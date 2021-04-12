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

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
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
