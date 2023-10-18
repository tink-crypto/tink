// Copyright 2023 Google LLC
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

#ifndef TINK_BIG_INTEGER_H_
#define TINK_BIG_INTEGER_H_

#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {

// Stores a BigInteger value as a big endian encoded string. Removes leading
// zeros prior to creation. This class is particularly useful for working with
// certain primitives which use big integers types for the parameters and key
// material.
class BigInteger {
 public:
  // Copyable and movable.
  BigInteger(const BigInteger& other) = default;
  BigInteger& operator=(const BigInteger& other) = default;
  BigInteger(BigInteger&& other) = default;
  BigInteger& operator=(BigInteger&& other) = default;

  // Creates a new BigInteger object that wraps a big endian encoded
  // string and removes leading zeros.
  explicit BigInteger(absl::string_view big_integer);

  // Returns the value of this BigInteger object.
  absl::string_view GetValue() const { return value_; }

  int64_t SizeInBytes() const { return value_.size(); }

  // Constant-time comparison operators.
  bool operator==(const BigInteger& other) const;
  bool operator!=(const BigInteger& other) const { return !(*this == other); }

 private:
  std::string value_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_BIG_INTEGER_H_
