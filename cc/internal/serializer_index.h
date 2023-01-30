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

#ifndef TINK_INTERNAL_SERIALIZER_INDEX_H_
#define TINK_INTERNAL_SERIALIZER_INDEX_H_

#include <string>
#include <typeindex>

#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {
namespace internal {

class SerializerIndex {
 public:
  // Create registry lookup key for the combination of the `KeyOrParameterT` and
  // `SerializationT` types. Useful for key and parameters serializers.
  template <typename KeyOrParameterT, typename SerializationT>
  static SerializerIndex Create() {
    return SerializerIndex(std::type_index(typeid(KeyOrParameterT)),
                           std::type_index(typeid(SerializationT)));
  }

  // Create registry lookup key for `SerializationT` type and `parameters`.
  // Useful for the serialization registry.
  template <typename SerializationT>
  static SerializerIndex Create(const Parameters& parameters) {
    return SerializerIndex(std::type_index(typeid(parameters)),
                           std::type_index(typeid(SerializationT)));
  }

  // Create registry lookup key for `SerializationT` type and `key`. Useful for
  // the serialization registry.
  template <typename SerializationT>
  static SerializerIndex Create(const Key& key) {
    return SerializerIndex(std::type_index(typeid(key)),
                           std::type_index(typeid(SerializationT)));
  }

  // Returns true if key/parameters index and serialization type index match.
  bool operator==(const SerializerIndex& other) const {
    return kp_index_ == other.kp_index_ &&
           serialization_index_ == other.serialization_index_;
  }

  // Required function to make `SerializerIndex` hashable for Abseil hash maps.
  template <typename H>
  friend H AbslHashValue(H h, const SerializerIndex& index) {
    return H::combine(std::move(h), index.kp_index_,
                      index.serialization_index_);
  }

 private:
  SerializerIndex(std::type_index kp_index, std::type_index serialization_index)
      : kp_index_(kp_index), serialization_index_(serialization_index) {}

  std::type_index kp_index_;
  std::type_index serialization_index_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_SERIALIZER_INDEX_H_
