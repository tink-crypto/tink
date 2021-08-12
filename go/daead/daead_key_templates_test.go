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
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testutil"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKeyTemplates(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	var testCases = []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{name: "AES256_SIV",
			template: daead.AESSIVKeyTemplate()},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := testutil.KeyTemplateProto("daead", tc.name)
			if err != nil {
				t.Fatalf("testutil.KeyTemplateProto('daead', tc.name) failed: %s", err)
			}
			if !proto.Equal(want, tc.template) {
				t.Errorf("template %s is not equal to '%s'", tc.name, tc.template)
			}
			if err := testEncryptDecrypt(tc.template); err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func testEncryptDecrypt(template *tinkpb.KeyTemplate) error {
	handle, err := keyset.NewHandle(template)
	if err != nil {
		return fmt.Errorf("keyset.NewHandle(template) failed: %v", err)
	}

	primitive, err := daead.New(handle)
	if err != nil {
		return fmt.Errorf("daead.New(handle) failed: %v", err)
	}

	var testInputs = []struct {
		plaintext []byte
		aad1      []byte
		aad2      []byte
	}{
		{
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte("extra data to authenticate"),
			aad2:      []byte("extra data to authenticate"),
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte(""),
			aad2:      []byte(""),
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      nil,
			aad2:      nil,
		}, {
			plaintext: []byte(""),
			aad1:      nil,
			aad2:      nil,
		}, {
			plaintext: nil,
			aad1:      []byte("extra data to authenticate"),
			aad2:      []byte("extra data to authenticate"),
		}, {
			plaintext: nil,
			aad1:      []byte(""),
			aad2:      []byte(""),
		}, {
			plaintext: nil,
			aad1:      nil,
			aad2:      nil,
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte(""),
			aad2:      nil,
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      nil,
			aad2:      []byte(""),
		},
	}
	for _, ti := range testInputs {
		ciphertext, err := primitive.EncryptDeterministically(ti.plaintext, ti.aad1)
		if err != nil {
			return fmt.Errorf("encryption failed, error: %v", err)
		}
		decrypted, err := primitive.DecryptDeterministically(ciphertext, ti.aad2)
		if err != nil {
			return fmt.Errorf("decryption failed, error: %v", err)
		}

		if !bytes.Equal(ti.plaintext, decrypted) {
			return fmt.Errorf("decrypted data doesn't match plaintext, got: %q, want: %q", decrypted, ti.plaintext)
		}
	}
	return nil
}
