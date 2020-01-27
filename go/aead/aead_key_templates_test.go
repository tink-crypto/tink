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
	"errors"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_aead_go_proto"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestAESGCMKeyTemplates(t *testing.T) {
	// AES-GCM 128 bit
	template := aead.AES128GCMKeyTemplate()
	if err := checkAESGCMKeyTemplate(template, uint32(16), tinkpb.OutputPrefixType_TINK); err != nil {
		t.Errorf("invalid AES-128 GCM key template: %s", err)
	}
	if err := testEncryptDecrypt(template, testutil.AESGCMTypeURL); err != nil {
		t.Errorf("%v", err)
	}

	// AES-GCM 256 bit
	template = aead.AES256GCMKeyTemplate()
	if err := checkAESGCMKeyTemplate(template, uint32(32), tinkpb.OutputPrefixType_TINK); err != nil {
		t.Errorf("invalid AES-256 GCM key template: %s", err)
	}
	if err := testEncryptDecrypt(template, testutil.AESGCMTypeURL); err != nil {
		t.Errorf("%v", err)
	}

	// AES-GCM 256 bit No Prefix
	template = aead.AES256GCMNoPrefixKeyTemplate()
	if err := checkAESGCMKeyTemplate(template, uint32(32), tinkpb.OutputPrefixType_RAW); err != nil {
		t.Errorf("invalid AES-256 GCM No Prefix key template: %s", err)
	}
	if err := testEncryptDecrypt(template, testutil.AESGCMTypeURL); err != nil {
		t.Errorf("%v", err)
	}
}

func checkAESGCMKeyTemplate(template *tinkpb.KeyTemplate, keySize uint32, outputPrefixType tinkpb.OutputPrefixType) error {
	if template.TypeUrl != testutil.AESGCMTypeURL {
		return fmt.Errorf("incorrect type url")
	}
	if template.OutputPrefixType != outputPrefixType {
		return fmt.Errorf("incorrect output prefix type")
	}
	keyFormat := new(gcmpb.AesGcmKeyFormat)
	err := proto.Unmarshal(template.Value, keyFormat)
	if err != nil {
		return fmt.Errorf("cannot deserialize key format: %s", err)
	}
	if keyFormat.KeySize != keySize {
		return fmt.Errorf("incorrect key size, expect %d, got %d", keySize, keyFormat.KeySize)
	}
	return nil
}

func TestAESCTRHMACAEADKeyTemplates(t *testing.T) {
	// AES-CTR 128 bit with HMAC SHA-256
	template := aead.AES128CTRHMACSHA256KeyTemplate()
	if err := checkAESCTRHMACAEADKeyTemplate(template, 16, 16, 16); err != nil {
		t.Errorf("invalid AES-128 CTR HMAC SHA256 key template: %s", err)
	}

	if err := testEncryptDecrypt(template, testutil.AESCTRHMACAEADTypeURL); err != nil {
		t.Errorf("%v", err)
	}

	// AES-CTR 256 bit with HMAC SHA-256
	template = aead.AES256CTRHMACSHA256KeyTemplate()
	if err := checkAESCTRHMACAEADKeyTemplate(template, 32, 16, 32); err != nil {
		t.Errorf("invalid AES-256 CTR HMAC SHA256 key template: %s", err)
	}
	if err := testEncryptDecrypt(template, testutil.AESCTRHMACAEADTypeURL); err != nil {
		t.Errorf("%v", err)
	}
}

func checkAESCTRHMACAEADKeyTemplate(template *tinkpb.KeyTemplate, keySize, ivSize, tagSize uint32) error {
	if template.TypeUrl != testutil.AESCTRHMACAEADTypeURL {
		return fmt.Errorf("incorrect type url")
	}
	keyFormat := new(ctrhmacpb.AesCtrHmacAeadKeyFormat)
	err := proto.Unmarshal(template.Value, keyFormat)
	if err != nil {
		return fmt.Errorf("cannot deserialize key format: %s", err)
	}
	if keyFormat.AesCtrKeyFormat.KeySize != keySize {
		return fmt.Errorf("incorrect key size, expect %d, got %d", keySize, keyFormat.AesCtrKeyFormat.KeySize)
	}
	if keyFormat.AesCtrKeyFormat.Params.IvSize != ivSize {
		return fmt.Errorf("incorrect IV size, expect %d, got %d", ivSize, keyFormat.AesCtrKeyFormat.Params.IvSize)
	}
	if keyFormat.HmacKeyFormat.KeySize != 32 {
		return fmt.Errorf("incorrect HMAC key size, expect 32, got %d", keyFormat.HmacKeyFormat.KeySize)
	}
	if keyFormat.HmacKeyFormat.Params.TagSize != tagSize {
		return fmt.Errorf("incorrect HMAC tag size, expect %d, got %d", tagSize, keyFormat.HmacKeyFormat.Params.TagSize)
	}
	if keyFormat.HmacKeyFormat.Params.Hash != commonpb.HashType_SHA256 {
		return fmt.Errorf("incorrect HMAC hash, expect %q, got %q", commonpb.HashType_SHA256, keyFormat.HmacKeyFormat.Params.Hash)
	}
	return nil
}

func TestChaCha20Poly1305KeyTemplate(t *testing.T) {
	template := aead.ChaCha20Poly1305KeyTemplate()
	if template.TypeUrl != testutil.ChaCha20Poly1305TypeURL {
		t.Errorf("incorrect type url: %v, expected %v", template.TypeUrl, testutil.ChaCha20Poly1305TypeURL)
	}
	if err := testEncryptDecrypt(template, testutil.ChaCha20Poly1305TypeURL); err != nil {
		t.Errorf("%v", err)
	}
}

func TestXChaCha20Poly1305KeyTemplate(t *testing.T) {
	template := aead.XChaCha20Poly1305KeyTemplate()
	if template.TypeUrl != testutil.XChaCha20Poly1305TypeURL {
		t.Errorf("incorrect type url: %v, expected %v", template.TypeUrl, testutil.XChaCha20Poly1305TypeURL)
	}
	if err := testEncryptDecrypt(template, testutil.XChaCha20Poly1305TypeURL); err != nil {
		t.Errorf("%v", err)
	}
}

func testEncryptDecrypt(template *tinkpb.KeyTemplate, typeURL string) error {
	key, err := registry.NewKey(template)
	if err != nil {
		return fmt.Errorf("failed to get key from template, error: %v", err)
	}

	sk, err := proto.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to serialize key, error: %v", err)
	}

	p, err := registry.Primitive(typeURL, sk)
	if err != nil {
		return fmt.Errorf("failed to get primitive from serialized key, error: %v", err)
	}

	primitive, ok := p.(tink.AEAD)
	if !ok {
		return errors.New("failed to convert AEAD primitive")
	}

	plaintext := []byte("some data to encrypt")
	aad := []byte("extra data to authenticate")
	ciphertext, err := primitive.Encrypt(plaintext, aad)
	if err != nil {
		return fmt.Errorf("encryption failed, error: %v", err)
	}
	decrypted, err := primitive.Decrypt(ciphertext, aad)
	if err != nil {
		return fmt.Errorf("decryption failed, error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		return fmt.Errorf("decrypted data doesn't match plaintext, got: %q, want: %q", decrypted, plaintext)
	}

	return nil
}
