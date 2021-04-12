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
	"io/ioutil"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKeyTemplates(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	var testCases = []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AES128_GCM_HKDF_4KB",
			template: streamingaead.AES128GCMHKDF4KBKeyTemplate(),
		},
		{
			name:     "AES128_GCM_HKDF_1MB",
			template: streamingaead.AES128GCMHKDF1MBKeyTemplate(),
		},
		{
			name:     "AES256_GCM_HKDF_4KB",
			template: streamingaead.AES256GCMHKDF4KBKeyTemplate(),
		}, {
			name:     "AES256_GCM_HKDF_1MB",
			template: streamingaead.AES256GCMHKDF1MBKeyTemplate(),
		}, {
			name:     "AES128_CTR_HMAC_SHA256_4KB",
			template: streamingaead.AES128CTRHMACSHA256Segment4KBKeyTemplate(),
		},
		{
			name:     "AES128_CTR_HMAC_SHA256_1MB",
			template: streamingaead.AES128CTRHMACSHA256Segment1MBKeyTemplate(),
		},
		{
			name:     "AES256_CTR_HMAC_SHA256_4KB",
			template: streamingaead.AES256CTRHMACSHA256Segment4KBKeyTemplate(),
		},
		{
			name:     "AES256_CTR_HMAC_SHA256_1MB",
			template: streamingaead.AES256CTRHMACSHA256Segment1MBKeyTemplate(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := testutil.KeyTemplateProto("streamingaead", tc.name)
			if err != nil {
				t.Fatalf(err.Error())
			}
			if !proto.Equal(want, tc.template) {
				t.Errorf("template %s is not equal to '%s'", tc.name, tc.template)
			}
			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				t.Fatalf("keyset.NewHandle(template) failed: %v", err)
			}
			primitive, err := streamingaead.New(handle)
			if err != nil {
				t.Fatalf("aead.New(handle) failed: %v", err)
			}

			plaintext := []byte("some data to encrypt")
			aad := []byte("extra data to authenticate")
			buf := &bytes.Buffer{}
			w, err := primitive.NewEncryptingWriter(buf, aad)
			if err != nil {
				t.Fatalf("primitive.NewEncryptingWriter(buf, aad) failed: %v", err)
			}
			if _, err := w.Write(plaintext); err != nil {
				t.Fatalf("w.Write(plaintext) failed: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("w.Close() failed: %v", err)
			}

			r, err := primitive.NewDecryptingReader(buf, aad)
			if err != nil {
				t.Fatalf("primitive.NewDecryptingReader(buf, aad) failed: %v", err)
			}
			decrypted, err := ioutil.ReadAll(r)
			if err != nil {
				t.Fatalf("ioutil.ReadAll(r) failed: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted data doesn't match plaintext, got: %q, want: ''", decrypted)
			}
		})
	}
}
