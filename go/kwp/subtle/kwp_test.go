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

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/tink/go/kwp/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
)

func TestWrapUnwrap(t *testing.T) {
	kek := random.GetRandomBytes(16)
	cipher, err := subtle.NewKWP(kek)
	if err != nil {
		t.Fatalf("failed to make kwp, error: %v", err)
	}

	for i := uint32(16); i < 128; i++ {
		t.Run(fmt.Sprintf("MessageSize%d", i), func(t *testing.T) {
			toWrap := random.GetRandomBytes(i)

			wrapped, err := cipher.Wrap(toWrap)
			if err != nil {
				t.Fatalf("failed to wrap, error: %v", err)
			}

			unwrapped, err := cipher.Unwrap(wrapped)
			if err != nil {
				t.Fatalf("failed to unwrap, error: %v", err)
			}

			if !bytes.Equal(toWrap, unwrapped) {
				t.Error("unwrapped doesn't match original key")
			}
		})
	}
}

func TestKeySizes(t *testing.T) {
	for i := 0; i < 255; i++ {
		expectSuccess := i == 16 || i == 32
		t.Run(fmt.Sprintf("KeySize%d", i), func(t *testing.T) {
			_, err := subtle.NewKWP(make([]byte, i))

			if expectSuccess && err != nil {
				t.Errorf("failed to create KWP: %v", err)
			}

			if !expectSuccess && err == nil {
				t.Error("created KWP with invalid key size")
			}
		})

	}
}

func TestInvalidWrappingSizes(t *testing.T) {
	kek := random.GetRandomBytes(16)
	cipher, err := subtle.NewKWP(kek)
	if err != nil {
		t.Fatalf("failed to make kwp, error: %v", err)
	}

	for i := 0; i < 16; i++ {
		t.Run(fmt.Sprintf("KeySize%d", i), func(t *testing.T) {
			if _, err := cipher.Wrap(make([]byte, i)); err == nil {
				t.Error("wrapped a short key")
			}
		})
	}
}

type KwpCase struct {
	testutil.WycheproofCase
	Key        string `json:"key"`
	Message    string `json:"msg"`
	Ciphertext string `json:"ct"`
}

type KwpGroup struct {
	testutil.WycheproofGroup
	KeySize int        `json:"keySize"`
	Tests   []*KwpCase `json:"tests"`
}

type KwpSuite struct {
	testutil.WycheproofSuite
	Groups []*KwpGroup `json:"testGroups"`
}

func TestWycheproofCases(t *testing.T) {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}
	f, err := os.Open(filepath.Join(srcDir, "wycheproof/testvectors/kwp_test.json"))
	if err != nil {
		t.Fatalf("cannot open file %s", err)
	}
	parser := json.NewDecoder(f)
	suite := new(KwpSuite)
	if err := parser.Decode(suite); err != nil {
		t.Fatalf("cannot decode test data: %s", err)
	}

	for _, group := range suite.Groups {
		if group.KeySize == 192 {
			continue
		}

		for _, test := range group.Tests {
			caseName := fmt.Sprintf("%s-%s(%d):Case-%d",
				suite.Algorithm, group.Type, group.KeySize, test.CaseID)
			t.Run(caseName, func(t *testing.T) { runWycheproofCase(t, test) })
		}
	}
}

func runWycheproofCase(t *testing.T, testCase *KwpCase) {
	kek, err := hex.DecodeString(testCase.Key)
	if err != nil {
		t.Fatalf("hex.DecodeString(testCase.Key) => %v", err)
	}

	msg, err := hex.DecodeString(testCase.Message)
	if err != nil {
		t.Fatalf("hex.DecodeString(testCase.Message) => %v", err)
	}

	ct, err := hex.DecodeString(testCase.Ciphertext)
	if err != nil {
		t.Fatalf("hex.DecodeString(testCase.Ciphertext) => %v", err)
	}

	cipher, err := subtle.NewKWP(kek)
	if err != nil {
		switch testCase.Result {
		case "valid":
			t.Fatalf("cannot create kwp, error: %v", err)
		case "invalid", "acceptable":
			return
		}
	}

	wrapped, err := cipher.Wrap(msg)
	switch testCase.Result {
	case "valid":
		if err != nil {
			t.Errorf("cannot wrap, error: %v", err)
		} else if !bytes.Equal(ct, wrapped) {
			t.Error("wrapped key mismatches test vector")
		}
	case "invalid":
		if err == nil && bytes.Equal(ct, wrapped) {
			t.Error("no error and wrapped key matches test vector for invalid case")
		}
	case "acceptable":
		if err == nil && !bytes.Equal(ct, wrapped) {
			t.Error("no error and wrapped key mismatches test vector for acceptable case")
		}
	}

	unwrapped, err := cipher.Unwrap(ct)
	switch testCase.Result {
	case "valid":
		if err != nil {
			t.Errorf("cannot unwrap, error: %v", err)
		} else if !bytes.Equal(msg, unwrapped) {
			t.Error("unwrapped key mismatches test vector")
		}
	case "invalid":
		if err == nil {
			t.Error("no error unwrapping invalid case")
		}
	case "acceptable":
		if err == nil && !bytes.Equal(msg, unwrapped) {
			t.Error("no error and unwrapped key mismatches plaintext")
		}
	}
}
