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

package subtle_test

import "github.com/google/tink/go/testutil"

type ecdhSuite struct {
	testutil.WycheproofSuite
	Schema     string       `json:"schema"`
	TestGroups []*ecdhGroup `json:"testGroups"`
}

type ecdhGroup struct {
	testutil.WycheproofGroup
	Curve    string      `json:"curve"`
	Encoding string      `json:"encoding"`
	Type     string      `json:"type"`
	Tests    []*ecdhCase `json:"tests"`
}

type ecdhCase struct {
	testutil.WycheproofCase
	Public  testutil.HexBytes `json:"public"`
	Private testutil.HexBytes `json:"private"`
	Shared  testutil.HexBytes `json:"shared"`
}
