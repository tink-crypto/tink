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
	"errors"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestAESSIVKeyTemplate(t *testing.T) {
	template := daead.AESSIVKeyTemplate()
	if template.TypeUrl != testutil.AESSIVTypeURL {
		t.Errorf("incorrect type url: %v, expected %v", template.TypeUrl, testutil.AESSIVTypeURL)
	}
	if err := testEncryptDecrypt(template); err != nil {
		t.Errorf("%v", err)
	}
}

func testEncryptDecrypt(template *tinkpb.KeyTemplate) error {
	key, err := registry.NewKey(template)
	if err != nil {
		return fmt.Errorf("failed to get key from template, error: %v", err)
	}

	sk, err := proto.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to serialize key, error: %v", err)
	}

	p, err := registry.Primitive(template.TypeUrl, sk)
	if err != nil {
		return fmt.Errorf("failed to get primitive from serialized key, error: %v", err)
	}

	primitive, ok := p.(tink.DeterministicAEAD)
	if !ok {
		return errors.New("failed to convert DeterministicAEAD primitive")
	}

	plaintext := []byte("some data to encrypt")
	aad := []byte("extra data to authenticate")
	ciphertext, err := primitive.EncryptDeterministically(plaintext, aad)
	if err != nil {
		return fmt.Errorf("encryption failed, error: %v", err)
	}
	decrypted, err := primitive.DecryptDeterministically(ciphertext, aad)
	if err != nil {
		return fmt.Errorf("decryption failed, error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		return fmt.Errorf("decrypted data doesn't match plaintext, got: %q, want: %q", decrypted, plaintext)
	}

	return nil
}
