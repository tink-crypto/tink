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

#ifndef TINK_INTERNAL_KEY_SERIALIZER_H_
#define TINK_INTERNAL_KEY_SERIALIZER_H_

#include <functional>
#include <typeindex>

#include "absl/functional/function_ref.h"
#include "tink/internal/serializer_index.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Non-template base class that can be used with internal registry map.
class KeySerializerBase {
 public:
  // Returns an index that can be used to look up the `KeySerializer`
  // object registered for the `KeyT` type in a registry.
  virtual SerializerIndex Index() const = 0;

  virtual ~KeySerializerBase() = default;
};

// Serializes `KeyT` objects into `SerializationT` objects.
template <typename KeyT, typename SerializationT>
class KeySerializer : public KeySerializerBase {
 public:
  // Creates a key serializer with serialization `function`. The referenced
  // `function` should outlive the created key serializer object.
  explicit KeySerializer(absl::FunctionRef<util::StatusOr<SerializationT>(
                             KeyT, SecretKeyAccessToken)>
                             function)
      : function_(function) {}

  // Returns the serialization of `key`.
  util::StatusOr<SerializationT> SerializeKey(
      KeyT key, SecretKeyAccessToken token) const {
    return function_(key, token);
  }

  SerializerIndex Index() const override {
    return SerializerIndex::Create<KeyT, SerializationT>();
  }

 private:
  std::function<util::StatusOr<SerializationT>(KeyT, SecretKeyAccessToken)>
      function_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEY_SERIALIZER_H_
