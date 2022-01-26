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

package internal_test

import (
	"strings"
	"testing"

	"github.com/google/tink/go/aead/internal"
)

func TestValidateAESKeySize(t *testing.T) {
	var i uint32
	for i = 0; i < 65; i++ {
		err := internal.ValidateAESKeySize(i)
		switch i {
		case 16, 32: // Valid key sizes.
			if err != nil {
				t.Errorf("want no error, got %v", err)
			}

		default:
			// Invalid key sizes.
			if err == nil {
				t.Errorf("invalid key size (%d) should not be accepted", i)
			}
			if !strings.Contains(err.Error(), "invalid AES key size; want 16 or 32") {
				t.Errorf("wrong error message; want a string starting with \"invalid AES key size; want 16 or 32\", got %v", err)
			}
		}
	}
}
