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

// Package mactest has testing utilities for the MAC primitive
package mactest

import (
	"github.com/google/tink/go/tink"
)

// AlwaysFailingMAC fails compute and verify operations.
type AlwaysFailingMAC struct {
	Error error
}

var _ (tink.MAC) = (*AlwaysFailingMAC)(nil)

// ComputeMAC returns an error on compute.
func (m *AlwaysFailingMAC) ComputeMAC(data []byte) ([]byte, error) {
	return nil, m.Error
}

// VerifyMAC returns an error on verify.
func (m *AlwaysFailingMAC) VerifyMAC(mac []byte, data []byte) error {
	return m.Error
}
