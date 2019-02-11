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

// Package insecure provides functions that create KeysetHandle from cleartext key material.
//
// This package contains dangerous functions, and is separate from the rest of Tink so that its
// usage can be restricted and audited.
package insecure

import (
	"errors"

	"github.com/google/tink/go/internal"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

var (
	keysetHandle     = internal.KeysetHandle.(func(*tinkpb.Keyset) *tink.KeysetHandle)
	errInvalidKeyset = errors.New("KeysetHandle: invalid keyset")
	errInvalidWriter = errors.New("KeysetWriter: invalid writer")
)

// NewKeysetHandleFromReader creates a KeysetHandle from an unencrypted keyset obtained via r.
func NewKeysetHandleFromReader(r tink.KeysetReader) (*tink.KeysetHandle, error) {
	if r == nil {
		return nil, errInvalidKeyset
	}
	ks, err := r.Read()
	if err != nil || ks == nil || len(ks.Key) == 0 {
		return nil, errInvalidKeyset
	}
	return keysetHandle(ks), nil
}

// WriteUnencryptedKeysetHandle exports the keyset from h to the given writer w without encrypting it.
// Storing secret key material in an unencrypted fashion is dangerous. If feasible, you should use
// func KeysetHandle.Write() instead.
func WriteUnencryptedKeysetHandle(h *tink.KeysetHandle, w tink.KeysetWriter) error {
	if h == nil {
		return errInvalidKeyset
	}
	if w == nil {
		return errInvalidWriter
	}
	return w.Write(h.Keyset())
}
