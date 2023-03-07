// Copyright 2020 Google LLC
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

package streamingaead_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	ghpb "github.com/google/tink/go/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	aesGCMHKDFTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"
)

func TestFactoryMultipleKeys(t *testing.T) {
	keyset := testutil.NewTestAESGCMHKDFKeyset()

	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		log.Fatal(err)
	}

	a, err := streamingaead.New(keysetHandle)
	if err != nil {
		t.Errorf("streamingaead.New failed: %s", err)
	}

	t.Run("Encrypt with a primary RAW key and decrypt with the keyset", func(t *testing.T) {
		if err := validateFactoryCipher(a, a); err != nil {
			t.Errorf("invalid cipher: %s", err)
		}
	})

	t.Run("Encrypt with a non-primary RAW key and decrypt with the keyset", func(t *testing.T) {
		rawKey := keyset.Key[1]
		if rawKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
			t.Errorf("expect a raw key")
		}
		keyset2 := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
		keysetHandle2, _ := testkeyset.NewHandle(keyset2)
		a2, err := streamingaead.New(keysetHandle2)
		if err != nil {
			t.Errorf("streamingaead.New failed: %s", err)
		}
		if err := validateFactoryCipher(a2, a); err != nil {
			t.Errorf("invalid cipher: %s", err)
		}
	})

	t.Run("Encrypt with a random key not in the keyset, decrypt with the keyset should fail", func(t *testing.T) {
		keyset2 := testutil.NewTestAESGCMHKDFKeyset()
		keysetHandle2, _ := testkeyset.NewHandle(keyset2)
		a2, err := streamingaead.New(keysetHandle2)
		if err != nil {
			t.Errorf("streamingaead.New failed: %s", err)
		}
		err = validateFactoryCipher(a2, a)
		if err == nil || !strings.Contains(err.Error(), "decryption failed") {
			t.Errorf("expect decryption to fail with random key: %s", err)
		}
	})
}

func validateFactoryCipher(encryptCipher tink.StreamingAEAD, decryptCipher tink.StreamingAEAD) error {
	tt := []int{1, 16, 4095, 4096, 4097, 16384}

	for _, t := range tt {
		if err := encryptDecrypt(encryptCipher, decryptCipher, t, 32); err != nil {
			return fmt.Errorf("failed plaintext-size=%d: %s", t, err)
		}
	}
	return nil
}

func encryptDecrypt(encryptCipher, decryptCipher tink.StreamingAEAD, ptSize, aadSize int) error {
	pt := random.GetRandomBytes(uint32(ptSize))
	aad := random.GetRandomBytes(uint32(aadSize))

	buf := &bytes.Buffer{}
	w, err := encryptCipher.NewEncryptingWriter(buf, aad)
	if err != nil {
		return fmt.Errorf("cannot create encrypt writer: %v", err)
	}
	if _, err := w.Write(pt); err != nil {
		return fmt.Errorf("error writing data: %v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("error closing writer: %v", err)
	}

	r, err := decryptCipher.NewDecryptingReader(buf, aad)
	if err != nil {
		return fmt.Errorf("cannot create decrypt reader: %v", err)
	}
	ptGot := make([]byte, len(pt)+1)
	n, err := io.ReadFull(r, ptGot)
	if err != nil && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("decryption failed: %v", err)
	}
	ptGot = ptGot[:n]
	if !bytes.Equal(pt, ptGot) {
		return fmt.Errorf("decryption failed")
	}
	return nil
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = streamingaead.New(wrongKH)
	if err == nil {
		t.Fatal("New() should fail with wrong *keyset.Handle")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(streamingaead.AES128GCMHKDF4KBKeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = streamingaead.New(goodKH)
	if err != nil {
		t.Fatalf("New() failed with good *keyset.Handle: %s", err)
	}
}

func TestFactoryWithKeysetWithTinkKeys(t *testing.T) {
	key := &ghpb.AesGcmHkdfStreamingKey{
		Version:  0,
		KeyValue: []byte("0123456789abcdef"),
		Params: &ghpb.AesGcmHkdfStreamingParams{
			CiphertextSegmentSize: 512,
			DerivedKeySize:        16,
			HkdfHashType:          commonpb.HashType_SHA1,
		},
	}
	value1, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal(key) err = %q, want nil", err)
	}
	key.KeyValue = []byte("ABCDEF0123456789")
	value2, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal(key) err = %q, want nil", err)
	}

	keyset := &tinkpb.Keyset{
		PrimaryKeyId: 1,
		Key: []*tinkpb.Keyset_Key{{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         aesGCMHKDFTypeURL,
				Value:           value1,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			KeyId:            1,
			Status:           tinkpb.KeyStatusType_ENABLED,
		}, &tinkpb.Keyset_Key{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         aesGCMHKDFTypeURL,
				Value:           value2,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			KeyId:            2,
			Status:           tinkpb.KeyStatusType_ENABLED,
		}},
	}

	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(keyset) err = %q, want nil", err)
	}
	a, err := streamingaead.New(keysetHandle)
	if err != nil {
		t.Errorf("streamingaead.New(keysetHandle) err = %q, want nil", err)
	}

	// TODO(b/129044084) Currently fails: TINK keys are ignored when decrypting
	if err := validateFactoryCipher(a, a); err == nil {
		t.Errorf("Encryption & Decryption with TINK key unexpectedly succeeded. Is b/129044084 fixed?")
	}
}
