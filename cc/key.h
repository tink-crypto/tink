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

#ifndef TINK_KEY_H_
#define TINK_KEY_H_

#include "absl/types/optional.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {

// Represents a cryptographic function.
//
// In Tink, `Key` objects represent cryptographic functions. For example, a
// `MacKey` represents the two functions: `computeMac()` and `verifyMac()`.
// The function `computeMac()` maps a byte sequence (possibly with additional
// randomness) to another byte sequence, called the tag. The function
// `verifyMac()` verifies the tag. A subclass `HmacKey` would contain all the
// information needed to properly compute an HMAC (e.g., including the hash
// function and tag length used).
//
// `Key` objects are lightweight, meaning they should have almost no
// dependencies except what is needed to represent the function. This allows
// `Key` objects to be used in contexts where dependencies need to be kept to a
// minimum.
class Key {
 public:
  // Returns a `Parameters` object containing all the information about the key
  // that is not randomly chosen.
  //
  // Implementations should ensure that 'GetParameters().HasIdRequirement()`
  // returns true if and only if `GetIdRequirement()` has a non-empty value.
  virtual const Parameters& GetParameters() const = 0;

  // Returns the required id if this key has an id requirement.  Otherwise,
  // returns an empty value if the key can have an arbitrary id.
  //
  // Some keys within a keyset are required to have a specific id to work
  // properly. This comes from the fact that Tink in some cases prefixes
  // ciphertexts or signatures with the string '0x01<id>', where the key id is
  // encoded in big endian format (see the documentation of the key type for
  // details). The key id provides a hint for which specific key was used to
  // generate the ciphertext or signature.
  virtual absl::optional<int> GetIdRequirement() const = 0;

  // Returns true if all `Key` object fields have identical values, including
  // the bytes for the raw key material.  Otherwise, returns false.
  //
  // NOTE: Implementations must perform equality checks in constant time.
  virtual bool operator==(const Key& other) const = 0;
  bool operator!=(const Key& other) const { return !(*this == other); }

  virtual ~Key() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEY_H_
