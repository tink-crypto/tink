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
#include <memory>
#include <typeindex>
#include <utility>

#include "absl/functional/function_ref.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serializer_index.h"
#include "tink/key.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Non-template base class that can be used with internal registry map.
class KeySerializer {
 public:
  // Returns the serialization of `key`.
  virtual util::StatusOr<std::unique_ptr<Serialization>> SerializeKey(
      const Key& key, absl::optional<SecretKeyAccessToken> token) const = 0;

  // Returns an index that can be used to look up the `KeySerializer`
  // object registered for the `KeyT` type in a registry.
  virtual SerializerIndex Index() const = 0;

  virtual ~KeySerializer() = default;
};

// Serializes `KeyT` objects into `SerializationT` objects.
template <typename KeyT, typename SerializationT>
class KeySerializerImpl : public KeySerializer {
 public:
  // Creates a key serializer with serialization `function`. The referenced
  // `function` should outlive the created key serializer object.
  explicit KeySerializerImpl(absl::FunctionRef<util::StatusOr<SerializationT>(
                                 KeyT, absl::optional<SecretKeyAccessToken>)>
                                 function)
      : function_(function) {}

  util::StatusOr<std::unique_ptr<Serialization>> SerializeKey(
      const Key& key,
      absl::optional<SecretKeyAccessToken> token) const override {
    const KeyT* kt = dynamic_cast<const KeyT*>(&key);
    if (kt == nullptr) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid key type for this key serializer.");
    }
    util::StatusOr<SerializationT> serialization = function_(*kt, token);
    if (!serialization.ok()) return serialization.status();
    return {absl::make_unique<SerializationT>(std::move(*serialization))};
  }

  SerializerIndex Index() const override {
    return SerializerIndex::Create<KeyT, SerializationT>();
  }

 private:
  std::function<util::StatusOr<SerializationT>(
      KeyT, absl::optional<SecretKeyAccessToken>)>
      function_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEY_SERIALIZER_H_
