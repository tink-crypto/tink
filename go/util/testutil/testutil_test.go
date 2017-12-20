// Copyright 2017 Google Inc.
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
  "testing"
  "bytes"
  "github.com/google/tink/go/tink/tink"
  "github.com/google/tink/go/util/testutil"
)

func TestDummyAead(t *testing.T) {
  // Assert that DummyAead implements the Aead interface.
  var _ tink.Aead = (*testutil.DummyAead)(nil)
}

func TestDummyMac(t *testing.T) {
  // Assert that DummyMac implements the Aead interface.
  var _ tink.Mac = (*testutil.DummyMac)(nil)
  // try to compute mac
  data := []byte{1, 2, 3, 4, 5}
  dummyMac := &testutil.DummyMac{Name: "Mac12347"}
  digest, err := dummyMac.ComputeMac(data)
  if err != nil {
    t.Errorf("unexpected error: %s", err)
  }
  if bytes.Compare(append(data, dummyMac.Name...), digest) != 0 {
    t.Errorf("incorrect digest")
  }
  if valid, err := dummyMac.VerifyMac(nil, nil); valid == false || err != nil {
    t.Errorf("unexpected result of VerifyMac")
  }
}