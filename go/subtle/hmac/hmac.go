// Copyright 2017 Google Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
////////////////////////////////////////////////////////////////////////////////
package hmac

import (
  "fmt"
  "hash"
  "crypto/hmac"
  "github.com/google/tink/go/subtle/subtleutil"
  "github.com/google/tink/go/tink/primitives"
)

const (
  // Minimum key size in bytes.
  minKeySizeInBytes = uint32(16)

  // Minimum tag size in bytes. This provides minimum 80-bit security strength.
  minTagSizeInBytes = uint32(10)
)

// Maximum tag size in bytes for each hash type
var maxTagSizeInBytes = map[string]uint32{
  "SHA1": uint32(20),
  "SHA256": uint32(32),
  "SHA512": uint32(64),
}

var errHmacInvalidInput = fmt.Errorf("hmac: invalid input")

// Hmac implementation of interface tink.Mac
type Hmac struct {
  HashFunc func() hash.Hash
  Key []byte
  TagSize uint32
}

// This makes sure that Hmac implements the tink.Mac interface
var _ tink.Mac = (*Hmac)(nil)

// New creates a new instance of Hmac
func New(hashAlg string, key []byte, tagSize uint32) (*Hmac, error) {
  keySize := uint32(len(key))
  if err := ValidateParams(hashAlg, keySize, tagSize); err != nil {
    return nil, fmt.Errorf("hmac: %s", err)
  }
  hashFunc := subtleutil.GetHashFunc(hashAlg)
  if hashFunc == nil {
    return nil, fmt.Errorf("hmac: invalid hash algorithm")
  }
  return &Hmac{
    HashFunc: hashFunc,
    Key: key,
    TagSize: tagSize,
  }, nil
}

// ValidateParams validates parameters of Hmac constructor.
func ValidateParams(hash string, keySize uint32, tagSize uint32) error {
  // validate tag size
  maxTagSize, found := maxTagSizeInBytes[hash]
  if !found {
    return fmt.Errorf("invalid hash algorithm")
  }
  if tagSize > maxTagSize {
    return fmt.Errorf("tag size too big")
  }
  if tagSize < minTagSizeInBytes {
    return fmt.Errorf("tag size too small")
  }
  // validate key size
  if keySize < minKeySizeInBytes {
    return fmt.Errorf("key too short")
  }
  return nil
}

// ComputeMac computes message authentication code (MAC) for the given data.
func (h *Hmac) ComputeMac(data []byte) ([]byte, error) {
  if data == nil {
    return nil, errHmacInvalidInput
  }
  mac := hmac.New(h.HashFunc, h.Key)
  mac.Write(data)
  tag := mac.Sum(nil)
  return tag[:h.TagSize], nil
}

// VerifyMac verifies whether the given MAC is a correct authentication code (MAC)
// the given data.
func (h *Hmac) VerifyMac(mac []byte, data []byte) (bool, error) {
  if mac == nil || data == nil {
    return false, errHmacInvalidInput
  }
  expectedMAC, err := h.ComputeMac(data)
  if err != nil {
    return false, err
  }
  return hmac.Equal(expectedMAC, mac), nil
}