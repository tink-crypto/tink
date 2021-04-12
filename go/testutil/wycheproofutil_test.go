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

package testutil_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/tink/go/testutil"
)

func TestPopulateSuite(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)

	// TODO(175520475): Test the HexBytes type.
	type AeadTest struct {
		testutil.WycheproofCase
		Key        string `json:"key"`
		IV         string `json:"iv"`
		AAD        string `json:"aad"`
		Message    string `json:"msg"`
		Ciphertext string `json:"ct"`
		Tag        string `json:"tag"`
	}

	type AeadGroup struct {
		testutil.WycheproofGroup
		Tests []*AeadTest `json:"tests"`
	}

	type AeadSuite struct {
		testutil.WycheproofSuite
		TestGroups []*AeadGroup `json:"testGroups"`
	}

	suite := new(AeadSuite)
	if err := testutil.PopulateSuite(suite, "aes_gcm_test.json"); err != nil {
		t.Fatalf("error populating suite: %s", err)
	}

	if suite.Algorithm != "AES-GCM" {
		t.Errorf("suite.Algorithm=%s, want AES-GCM", suite.Algorithm)
	}

	if suite.TestGroups[0].Tests[0].Key == "" {
		t.Error("suite.TestGroups[0].Tests[0].Key is empty")
	}
}

func TestPopulateSuite_FileOpenError(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)

	suite := new(testutil.WycheproofSuite)
	err := testutil.PopulateSuite(suite, "NON_EXISTENT_FILE")
	if err == nil {
		t.Error("succeeded with non-existent file")
	}
	if _, ok := err.(*os.PathError); !ok {
		t.Errorf("unexpected error for non-existent file: %s", err)
	}
}

func TestPopulateSuite_DecodeError(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)

	var suite *testutil.WycheproofSuite
	err := testutil.PopulateSuite(suite, "aes_gcm_test.json")
	if err == nil {
		t.Error("succeeded with nil suite")
	}
	if _, ok := err.(*json.InvalidUnmarshalError); !ok {
		t.Errorf("unexpected error for decode error: %s", err)
	}
}
