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
////////////////////////////////////////////////////////////////////////////////

// Package streamingprf provides implementations of streaming pseudorandom
// function families.
package streamingprf

import (
	"fmt"
	"io"

	"github.com/google/tink/go/core/registry"
)

// StreamingPRF is the interface used to represent a streaming pseudorandom
// function family for a specified key.
//
// It has the same properties as the PRF primitive.
type StreamingPRF interface {
	// Compute computes the PRF selected by the specified key on input and returns
	// the result via a reader.
	Compute(input []byte) io.Reader
}

func init() {
	if err := registry.RegisterKeyManager(new(hkdfStreamingPRFKeyManager)); err != nil {
		panic(fmt.Sprintf("streamingprf.init() failed: %v", err))
	}
}
