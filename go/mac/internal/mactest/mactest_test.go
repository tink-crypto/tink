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

package mactest_test

import (
	"errors"
	"testing"

	"github.com/google/tink/go/mac/internal/mactest"
)

func TestAlwaysFailingMACAlwayFails(t *testing.T) {
	wantErr := errors.New("panic at the kernel")
	p := &mactest.AlwaysFailingMAC{Error: wantErr}
	if _, err := p.ComputeMAC([]byte("valid_data")); !errors.Is(err, wantErr) {
		t.Errorf("p.ComputeMac() err = %v, want %v", err, wantErr)
	}
	if err := p.VerifyMAC([]byte("data"), []byte("tag")); !errors.Is(err, wantErr) {
		t.Errorf("p.VerifyMac() err = %v, want %v", err, wantErr)
	}
}
