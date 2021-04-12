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

type macSuite struct {
	testutil.WycheproofSuite
	TestGroups []*macGroup `json:"testGroups"`
}

type macGroup struct {
	testutil.WycheproofGroup
	KeySize uint32     `json:"keySize"`
	TagSize uint32     `json:"tagSize"`
	Type    string     `json:"type"`
	Tests   []*macCase `json:"tests"`
}

type macCase struct {
	testutil.WycheproofCase
	Key     testutil.HexBytes `json:"key"`
	Message testutil.HexBytes `json:"msg"`
	Tag     testutil.HexBytes `json:"tag"`
}

type hkdfSuite struct {
	testutil.WycheproofSuite
	TestGroups []*hkdfGroup `json:"testGroups"`
}

type hkdfGroup struct {
	testutil.WycheproofGroup
	KeySize uint32      `json:"keySize"`
	Type    string      `json:"type"`
	Tests   []*hkdfCase `json:"tests"`
}

type hkdfCase struct {
	testutil.WycheproofCase
	IKM  testutil.HexBytes `json:"ikm"`
	Salt testutil.HexBytes `json:"salt"`
	Info testutil.HexBytes `json:"info"`
	Size uint32            `json:"size"`
	OKM  testutil.HexBytes `json:"okm"`
}
