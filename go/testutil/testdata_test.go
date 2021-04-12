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

package testutil_test

import (
	"testing"

	"github.com/google/tink/go/testutil"
)

func TestKeyTemplateProto(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	template, err := testutil.KeyTemplateProto("aead", "AES256_GCM")
	if err != nil {
		t.Fatalf(err.Error())
	}
	if template.GetTypeUrl() != "type.googleapis.com/google.crypto.tink.AesGcmKey" {
		t.Errorf("Got template.GetTypeUrl()=%s, want 'type.googleapis.com/google.crypto.tink.AesGcmKey'", template.GetTypeUrl())
	}

	if _, err = testutil.KeyTemplateProto("aead", "UNKNOWN"); err == nil {
		t.Errorf("KeyTemplateProto(aead, UNKNOWN) succeeded, want fail.")
	}
}
