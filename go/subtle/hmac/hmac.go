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

/**
 * HMAC implementation using crypto package
 */

//TODO(thaidn): enforce some minimal value for key size and tag size.

package hmac

import (
  "crypto/hmac"
  "fmt"
  "hash"
)

// Context used for logging error
var context = "subtle/hmac"

type Hmac struct {
  HashFunc func() hash.Hash
  Key []byte
  TagSize uint32
}

/**
 * Computes message authentication code (MAC) for {@code data}.
 *
 * @return MAC value.
 */
func (h *Hmac) ComputeMac(data []byte) ([]byte, error) {
  if data == nil {
    return []byte{}, fmt.Errorf("%s: %s", context, "ComputeMac() called with nil")
  }
  mac := hmac.New(h.HashFunc, h.Key)
  mac.Write(data)
  tag := mac.Sum(nil)
  if uint32(len(tag)) < h.TagSize {
    return []byte{}, fmt.Errorf("%s: %s", context, "tag size is too large")
  }
  return tag[:h.TagSize], nil
}


/**
 * Verifies whether {@code mac} is a correct authentication code (MAC) for {@code data}.
 *
 * @return true if {@code mac} is correct; false otherwise.
 */
func (h *Hmac) VerifyMac(mac []byte, data []byte) (bool, error) {
  if mac == nil || data == nil {
    return false, fmt.Errorf("%s: %s", context, "VerifyMac() called with nil")
  }
  expectedMAC, err := h.ComputeMac(data)
  if err != nil {
    return false, err
  }
  return hmac.Equal(expectedMAC, mac), nil
}