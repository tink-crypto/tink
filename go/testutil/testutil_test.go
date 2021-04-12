// Copyright 2018 Google LLC
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
	"bytes"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
)

func TestDummyAEAD(t *testing.T) {
	// Assert that DummyAEAD implements the AEAD interface.
	var _ tink.AEAD = (*testutil.DummyAEAD)(nil)
}

func TestDummyMAC(t *testing.T) {
	// Assert that DummyMAC implements the MAC interface.
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

func fillByteArray(b byte, length int) []byte {
	result := []byte{}
	for i := 0; i < length; i++ {
		result = append(result, b)
	}
	return result
}

func TestUniformString(t *testing.T) {
	if err := testutil.ZTestUniformString(fillByteArray(0xaa, 32)); err != nil {
		t.Errorf("Expected repeated 0xaa string to pass: %v", err)
	}
	if err := testutil.ZTestUniformString(fillByteArray(0x00, 32)); err == nil {
		t.Errorf("Expected to fail uniform distribution test for 32 zero bytes")
	}
	if err := testutil.ZTestUniformString(random.GetRandomBytes(32)); err != nil {
		t.Errorf("Expected random string to pass randomness test: %v", err)
	}
}

func TestCrossCorrelationUniformString(t *testing.T) {
	if err := testutil.ZTestCrosscorrelationUniformStrings(fillByteArray(0xaa, 32),
		fillByteArray(0x99, 32)); err != nil {
		t.Errorf("Expected 0xaa and 0x99 repeated 32 times each to have no cross correlation: %v", err)
	}
	if err := testutil.ZTestCrosscorrelationUniformStrings(fillByteArray(0xaa, 32),
		fillByteArray(0xaa, 32)); err == nil {
		t.Errorf("Expected 0xaa repeated 32 times to be cross correlated with itself")
	}
	if err := testutil.ZTestCrosscorrelationUniformStrings(random.GetRandomBytes(32),
		random.GetRandomBytes(32)); err != nil {
		t.Errorf("Expected random 32 byte strings to not be crosscorrelated: %v", err)
	}
}

func TestAutocorrelationUniformString(t *testing.T) {
	if err := testutil.ZTestAutocorrelationUniformString(fillByteArray(0xaa, 32)); err == nil {
		t.Errorf("Expected repeated string to show autocorrelation")
	}
	if err := testutil.ZTestAutocorrelationUniformString([]byte(
		"This is a text that is only ascii characters and therefore " +
			"not random. It needs quite a few characters before it has " +
			"enough to find a pattern, though, as it is text.")); err == nil {
		t.Errorf("Expected longish English ASCII test to be autocorrelated")
	}
	if err := testutil.ZTestAutocorrelationUniformString(random.GetRandomBytes(32)); err != nil {
		t.Errorf("Expected random 32 byte string to show not autocorrelation: %v", err)
	}
}
