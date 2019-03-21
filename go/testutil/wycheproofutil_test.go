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
	"io/ioutil"
	"testing"

	"github.com/google/tink/go/testutil"
)

func TestWycheproofParsing(t *testing.T) {

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

	bytes, err := ioutil.ReadFile("../../../wycheproof/testvectors/aes_gcm_test.json")
	if err != nil {
		t.Fatal(err)
	}

	suite := new(AeadSuite)
	err = json.Unmarshal(bytes, suite)
	if err != nil {
		t.Fatal(err)
	}

	if suite.Algorithm != "AES-GCM" {
		t.Errorf("suite.Algorithm=%s, want AES-GCM", suite.Algorithm)
	}

	if suite.TestGroups[0].Tests[0].Key == "" {
		t.Error("suite.TestGroups[0].Tests[0].Key is empty")
	}
}
