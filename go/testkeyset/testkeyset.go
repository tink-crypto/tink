// Copyright 2019 Google LLC
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

// Package testkeyset provides for test code methods to read or write cleartext keyset material.
package testkeyset

import (
	"errors"

	"github.com/google/tink/go/internal"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var (
	// KeysetHandle creates a keyset.Handle from cleartext key material.
	KeysetHandle = internal.KeysetHandle.(func(*tinkpb.Keyset) *keyset.Handle)
	// KeysetMaterial returns the key material contained in a keyset.Handle.
	KeysetMaterial = internal.KeysetMaterial.(func(*keyset.Handle) *tinkpb.Keyset)

	errInvalidKeyset = errors.New("cleartextkeyset: invalid keyset")
	errInvalidHandle = errors.New("cleartextkeyset: invalid handle")
	errInvalidReader = errors.New("cleartextkeyset: invalid reader")
	errInvalidWriter = errors.New("cleartextkeyset: invalid writer")
)

// NewHandle creates a new instance of Handle using the given keyset.
func NewHandle(ks *tinkpb.Keyset) (*keyset.Handle, error) {
	if ks == nil || len(ks.Key) == 0 {
		return nil, errInvalidKeyset
	}
	return KeysetHandle(ks), nil
}

// Read creates a keyset.Handle from a cleartext keyset obtained via r.
func Read(r keyset.Reader) (*keyset.Handle, error) {
	if r == nil {
		return nil, errInvalidReader
	}
	ks, err := r.Read()
	if err != nil || ks == nil || len(ks.Key) == 0 {
		return nil, errInvalidKeyset
	}
	return KeysetHandle(ks), nil
}

// Write exports the keyset from h to the given writer w without encrypting it.
// Storing secret key material in an unencrypted fashion is dangerous. If feasible, you should use
// func keyset.Handle.Write() instead.
func Write(h *keyset.Handle, w keyset.Writer) error {
	if h == nil {
		return errInvalidHandle
	}
	if w == nil {
		return errInvalidWriter
	}
	return w.Write(KeysetMaterial(h))
}
