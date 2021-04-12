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

// Package prf contains utilities to calculate pseudo random function families.
package prf

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

// The PRF interface is an abstraction for an element of a pseudo random
// function family, selected by a key. It has the following property:
//   * It is deterministic. PRF.compute(input, length) will always return the
//     same output if the same key is used. PRF.compute(input, length1) will be
//     a prefix of PRF.compute(input, length2) if length1 < length2 and the same
//     key is used.
//   * It is indistinguishable from a random function:
//     Given the evaluation of n different inputs, an attacker cannot
//     distinguish between the PRF and random bytes on an input different from
//     the n that are known.
// Use cases for PRF are deterministic redaction of PII, keyed hash functions,
// creating sub IDs that do not allow joining with the original dataset without
// knowing the key.
// While PRFs can be used in order to prove authenticity of a message, using the
// MAC interface is recommended for that use case, as it has support for
// verification, avoiding the security problems that often happen during
// verification, and having automatic support for key rotation. It also allows
// for non-deterministic MAC algorithms.
type PRF interface {
	// Computes the PRF selected by the underlying key on input and
	// returns the first outputLength bytes.
	// When choosing this parameter keep the birthday paradox in mind.
	// If you have 2^n different inputs that your system has to handle
	// set the output length (in bytes) to at least
	// ceil(n/4 + 4)
	// This corresponds to 2*n + 32 bits, meaning a collision will occur with
	// a probability less than 1:2^32. When in doubt, request a security review.
	// Returns a non ok status if the algorithm fails or if the output of
	// algorithm is less than outputLength.
	ComputePRF(input []byte, outputLength uint32) ([]byte, error)
}

// Set is a set of PRFs. A Tink Keyset can be converted into a set of PRFs using this primitive. Every
// key in the keyset corresponds to a PRF in the prf.Set.
// Every PRF in the set is given an ID, which is the same ID as the key id in
// the Keyset.
type Set struct {
	// PrimaryID is the key ID marked as primary in the corresponding Keyset.
	PrimaryID uint32
	// PRFs maps key IDs to their corresponding PRF.
	PRFs map[uint32]PRF
}

// ComputePrimaryPRF is equivalent to set.PRFs[set.PrimaryID].ComputePRF(input, outputLength).
func (s Set) ComputePrimaryPRF(input []byte, outputLength uint32) ([]byte, error) {
	prf, ok := s.PRFs[s.PrimaryID]
	if !ok {
		return nil, fmt.Errorf("Could not find primary ID %d in prf.Set", s.PrimaryID)
	}
	return prf.ComputePRF(input, outputLength)
}

func init() {
	if err := registry.RegisterKeyManager(newHMACPRFKeyManager()); err != nil {
		panic(fmt.Sprintf("prf.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(newHKDFPRFKeyManager()); err != nil {
		panic(fmt.Sprintf("prf.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(newAESCMACPRFKeyManager()); err != nil {
		panic(fmt.Sprintf("prf.init() failed: %v", err))
	}
}
