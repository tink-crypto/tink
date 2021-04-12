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

package testutil

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const (
	wycheproofDir = "wycheproof/testvectors"
)

// WycheproofSuite represents the common elements of the top level
// object in a Wycheproof json file. Implementations should embed
// WycheproofSuite in a struct that strongly types the testGroups
// field. See wycheproofutil_test.go for an example.
type WycheproofSuite struct {
	Algorithm        string            `json:"algorithm"`
	GeneratorVersion string            `json:"generatorVersion"`
	NumberOfTests    int               `json:"numberOfTests"`
	Notes            map[string]string `json:"notes"`
}

// WycheproofGroup represents the common elements of a testGroups
// object in a Wycheproof suite. Implementations should embed
// WycheproofGroup in a struct that strongly types its list of cases.
// See wycheproofutil_test.go for an example.
type WycheproofGroup struct {
	Type string `json:"type"`
}

// WycheproofCase represents the common elements of a tests object
// in a Wycheproof group. Implementation should embed WycheproofCase
// in a struct that contains fields specific to the test type.
// See wycheproofutil_test.go for an example.
type WycheproofCase struct {
	CaseID  int      `json:"tcId"`
	Comment string   `json:"comment"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

// HexBytes is a helper type for unmarshalling a byte sequence represented as a
// hex encoded string.
type HexBytes []byte

// UnmarshalText converts a hex encoded string into a sequence of bytes.
func (a *HexBytes) UnmarshalText(text []byte) error {
	decoded, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}

	*a = decoded
	return nil
}

// PopulateSuite opens filename from the Wycheproof test vectors directory and
// populates suite with the decoded JSON data.
//
// When using this in a test function, the function should start with
// SkipTestIfTestSrcDirIsNotSet(), to expediently skip the test.
func PopulateSuite(suite interface{}, filename string) error {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		return errors.New("TEST_SRCDIR not found")
	}
	f, err := os.Open(filepath.Join(srcDir, wycheproofDir, filename))
	if err != nil {
		return err
	}
	parser := json.NewDecoder(f)
	if err := parser.Decode(suite); err != nil {
		return err
	}
	return nil
}
