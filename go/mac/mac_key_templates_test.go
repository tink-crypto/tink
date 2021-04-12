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
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKeyTemplates(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	var testCases = []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{name: "HMAC_SHA256_128BITTAG",
			template: mac.HMACSHA256Tag128KeyTemplate()},
		{name: "HMAC_SHA256_256BITTAG",
			template: mac.HMACSHA256Tag256KeyTemplate()},
		{name: "HMAC_SHA512_256BITTAG",
			template: mac.HMACSHA512Tag256KeyTemplate()},
		{name: "HMAC_SHA512_512BITTAG",
			template: mac.HMACSHA512Tag512KeyTemplate()},
		{name: "AES_CMAC",
			template: mac.AESCMACTag128KeyTemplate()},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := testutil.KeyTemplateProto("mac", tc.name)
			if err != nil {
				t.Fatalf("testutil.KeyTemplateProto('mac', tc.name) failed: %s", err)
			}
			if !proto.Equal(want, tc.template) {
				t.Errorf("template %s is not equal to '%s'", tc.name, tc.template)
			}

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				t.Fatalf("keyset.NewHandle(tc.template) failed: %v", err)
			}
			primitive, err := mac.New(handle)
			if err != nil {
				t.Fatalf("mac.New(handle) failed: %v", err)
			}

			var testInputs = []struct {
				message1 []byte
				message2 []byte
			}{
				{
					message1: []byte("this data needs to be authenticated"),
					message2: []byte("this data needs to be authenticated"),
				}, {
					message1: []byte(""),
					message2: []byte(""),
				}, {
					message1: []byte(""),
					message2: nil,
				}, {
					message1: nil,
					message2: []byte(""),
				}, {
					message1: nil,
					message2: nil,
				},
			}
			for _, ti := range testInputs {
				tag, err := primitive.ComputeMAC(ti.message1)
				if err != nil {
					t.Fatalf("primitive.ComputeMAC(ti.message1) failed: %v", err)
				}
				if primitive.VerifyMAC(tag, ti.message2); err != nil {
					t.Errorf("primitive.VerifyMAC(tag, ti.message2) failed: %v", err)
				}
			}
		})
	}
}
