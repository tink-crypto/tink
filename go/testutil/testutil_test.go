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
	"bytes"
	"testing"

	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
)

func TestDummyAEAD(t *testing.T) {
	// Assert that DummyAEAD implements the AEAD interface.
	var _ tink.AEAD = (*testutil.DummyAEAD)(nil)
}

func TestDummyMAC(t *testing.T) {
	// Assert that DummyMAC implements the AEAD interface.
	var _ tink.MAC = (*testutil.DummyMAC)(nil)
	// try to compute mac
	data := []byte{1, 2, 3, 4, 5}
	dummyMAC := &testutil.DummyMAC{Name: "Mac12347"}
	digest, err := dummyMAC.ComputeMAC(data)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if !bytes.Equal(append(data, dummyMAC.Name...), digest) {
		t.Errorf("incorrect digest")
	}
	if err := dummyMAC.VerifyMAC(nil, nil); err != nil {
		t.Errorf("unexpected result of VerifyMAC")
	}
}
