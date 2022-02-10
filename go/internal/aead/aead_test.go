// Copyright 2022 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

package aead_test

import (
	"testing"

	"github.com/google/tink/go/internal/aead"
)

func TestValidateAESKeySize(t *testing.T) {
	for _, keySize := range []uint32{8, 16, 24, 32, 40} {
		err := aead.ValidateAESKeySize(keySize)
		if keySize == 16 || keySize == 32 {
			if err != nil {
				t.Errorf("ValidateAESKeySize(%d): got err %q, want success", keySize, err)
			}
		} else if err == nil {
			t.Errorf("ValidateAESKeySize(%d): got success, want error", keySize)
		}
	}
}
