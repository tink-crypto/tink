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

package streamingprf

import (
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
	"github.com/google/tink/go/subtle"
)

// minHKDFStreamingPRFKeySize is the minimum allowed key size in bytes.
const minHKDFStreamingPRFKeySize = 32

// hkdfStreamingPRF is a HKDF Streaming PRF that implements StreamingPRF.
type hkdfStreamingPRF struct {
	h    func() hash.Hash
	key  []byte
	salt []byte
}

// Asserts that hkdfStreamingPRF implements the StreamingPRF interface.
var _ StreamingPRF = (*hkdfStreamingPRF)(nil)

// newHKDFStreamingPRF constructs a new hkdfStreamingPRF using hashName, key,
// and salt. Salt can be nil.
func newHKDFStreamingPRF(hashName string, key, salt []byte) (*hkdfStreamingPRF, error) {
	if err := validateHKDFStreamingPRFParams(hashName, len(key)); err != nil {
		return nil, err
	}
	return &hkdfStreamingPRF{
		h:    subtle.GetHashFunc(hashName),
		key:  key,
		salt: salt,
	}, nil
}

// Compute computes and returns the HKDF as a Reader.
func (h *hkdfStreamingPRF) Compute(data []byte) io.Reader {
	return hkdf.New(h.h, h.key, h.salt, data)
}

func validateHKDFStreamingPRFParams(hash string, keySize int) error {
	if hash != "SHA256" && hash != "SHA512" {
		return fmt.Errorf("only SHA-256, SHA-512 allowed for HKDF")
	}
	if keySize < minHKDFStreamingPRFKeySize {
		return fmt.Errorf("key too short, require %d-bytes: %d", minHKDFStreamingPRFKeySize, keySize)
	}
	return nil
}
