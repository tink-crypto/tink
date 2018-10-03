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
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestAESGCMKeyTemplates(t *testing.T) {
	// AES-GCM 128 bit
	template := aead.AES128GCMKeyTemplate()
	if err := checkAESGCMKeyTemplate(template, uint32(16)); err != nil {
		t.Errorf("invalid AES-128 GCM key template: %s", err)
	}
	// AES-GCM 256 bit
	template = aead.AES256GCMKeyTemplate()
	if err := checkAESGCMKeyTemplate(template, uint32(32)); err != nil {
		t.Errorf("invalid AES-256 GCM key template: %s", err)
	}
}

func checkAESGCMKeyTemplate(template *tinkpb.KeyTemplate, keySize uint32) error {
	if template.TypeUrl != aead.AESGCMTypeURL {
		return fmt.Errorf("incorrect type url")
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
