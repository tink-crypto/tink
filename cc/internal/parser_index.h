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

#ifndef TINK_INTERNAL_PARSER_INDEX_H_
#define TINK_INTERNAL_PARSER_INDEX_H_

#include <string>
#include <typeindex>

#include "absl/strings/string_view.h"
#include "tink/internal/serialization.h"

namespace crypto {
namespace tink {
namespace internal {

class ParserIndex {
 public:
  // Create registry lookup key for a `SerializationT` type object with
  // `object_identifier`. Useful for key and parameters parsers.
  template <typename SerializationT>
  static ParserIndex Create(absl::string_view object_identifier) {
    return ParserIndex(std::type_index(typeid(SerializationT)),
                       object_identifier);
  }

  // Create registry lookup key for `serialization`. Useful for the
  // serialization registry.
  static ParserIndex Create(const Serialization& serialization) {
    return ParserIndex(std::type_index(typeid(serialization)),
                       serialization.ObjectIdentifier());
  }

  // Returns true if serialization type index and object identifier match.
  bool operator==(const ParserIndex& other) const {
    return index_ == other.index_ &&
           object_identifier_ == other.object_identifier_;
  }

  // Required function to make `ParserIndex` hashable for Abseil hash maps.
  template <typename H>
  friend H AbslHashValue(H h, const ParserIndex& index) {
    return H::combine(std::move(h), index.index_, index.object_identifier_);
  }

 private:
  ParserIndex(std::type_index index, absl::string_view object_identifier)
      : index_(index), object_identifier_(object_identifier) {}

  std::type_index index_;
  std::string object_identifier_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PARSER_INDEX_H_
