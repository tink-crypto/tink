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

#ifndef TINK_KEY_FORMAT_H_
#define TINK_KEY_FORMAT_H_

namespace crypto {
namespace tink {

// Represents a cryptographic function without the actual key material.
//
// In Tink, a `Key` represents a set of cryptographic functions. A `KeyFormat`
// contains all the information about the function that is not randomly
// chosen with each instance.
class KeyFormat {
 public:
  // Returns true if a key created with this format has to have a particular id
  // when it is in a keyset.  Otherwise, returns false.
  //
  // In Tink, certain keys change their behavior depending on the key id (e.g.,
  // an `Aead` object may add a prefix containing the big endian encoding of the
  // key id to the ciphertext). In this case, such a key should require a unique
  // id in `Key::GetIdRequirement()` and return true.
  virtual bool HasIdRequirement() const = 0;

  // Returns true if all `KeyFormat` fields have identical values.  Otherwise,
  // returns false.
  virtual bool operator==(const KeyFormat& other) const = 0;
  bool operator!=(const KeyFormat& other) const { return !(*this == other); }

  virtual ~KeyFormat() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEY_FORMAT_H_
