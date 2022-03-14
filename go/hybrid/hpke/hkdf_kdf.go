// Copyright 2021 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

package hpke

import (
	"crypto"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// hkdfKDF is a HKDF HPKE KDF variant that implements interface kdf.
type hkdfKDF struct {
	// HPKE KDF algorithm identifier.
	kdfID        uint16
	hashFunction crypto.Hash
}

var _ kdf = (*hkdfKDF)(nil)

// newHKDFKDF constructs a HKDF HPKE KDF using hashFunction.
func newHKDFKDF(hashFunction string) (*hkdfKDF, error) {
	if hashFunction == sha256 {
		return &hkdfKDF{kdfID: hkdfSHA256, hashFunction: crypto.SHA256}, nil
	}
	return nil, fmt.Errorf("hash function %s is not supported", hashFunction)
}

func (h *hkdfKDF) labeledExtract(salt, ikm []byte, ikmLabel string, suiteID []byte) []byte {
	return hkdf.Extract(h.hashFunction.New, labelIKM(ikmLabel, ikm, suiteID), salt)
}

func (h *hkdfKDF) labeledExpand(prk, info []byte, infoLabel string, suiteID []byte, length int) ([]byte, error) {
	labeledInfo, err := labelInfo(infoLabel, info, suiteID, length)
	if err != nil {
		return nil, err
	}
	reader := hkdf.Expand(h.hashFunction.New, prk, labeledInfo)
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (h *hkdfKDF) extractAndExpand(salt, ikm []byte, ikmLabel string, info []byte, infoLabel string, suiteID []byte, length int) ([]byte, error) {
	prk := h.labeledExtract(salt, ikm, ikmLabel, suiteID)
	return h.labeledExpand(prk, info, infoLabel, suiteID, length)
}

func (h *hkdfKDF) id() uint16 {
	return h.kdfID
}
