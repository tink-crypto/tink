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

package hybrid

import (
	"bytes"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKeyTemplates(t *testing.T) {
	var testCases = []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{name: "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
			template: ECIESHKDFAES128GCMKeyTemplate()},
		{name: "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
			template: ECIESHKDFAES128CTRHMACSHA256KeyTemplate()},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := testutil.KeyTemplateProto("hybrid", tc.name)
			if err != nil {
				t.Fatalf("testutil.KeyTemplateProto('hybrid', tc.name) failed: %s", err)
			}
			if !proto.Equal(want, tc.template) {
				t.Errorf("template %s is not equal to '%s'", tc.name, tc.template)
			}

			privateHandle, err := keyset.NewHandle(tc.template)
			if err != nil {
				t.Fatalf("keyset.NewHandle(tc.template) failed: %s", err)
			}
			publicHandle, err := privateHandle.Public()
			if err != nil {
				t.Fatalf("privateHandle.Public() failed: %s", err)
			}
			enc, err := NewHybridEncrypt(publicHandle)
			if err != nil {
				t.Fatalf("NewHybridEncrypt(publicHandle) failed: %s", err)
			}
			plaintext := []byte("this data needs to be encrypted")
			encryptionContext := []byte("encryption context")
			ciphertext, err := enc.Encrypt(plaintext, encryptionContext)
			if err != nil {
				t.Fatalf("enc.Encrypt(plaintext, encryptionContext) failed: %s", err)
			}

			dec, err := NewHybridDecrypt(privateHandle)
			if err != nil {
				t.Fatalf("NewHybridDecrypt(privateHandle) failed: %s", err)
			}
			decrypted, err := dec.Decrypt(ciphertext, encryptionContext)
			if err != nil {
				t.Fatalf("dec.Decrypt(ciphertext, encryptionContext) failed: %s", err)
			}
			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("decrypted data doesn't match plaintext, got: %q, want: %q", decrypted, plaintext)
			}
		})
	}
}
