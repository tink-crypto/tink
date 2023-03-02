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

#ifndef TINK_INTERNAL_SERIALIZATION_REGISTRY_H_
#define TINK_INTERNAL_SERIALIZATION_REGISTRY_H_

#include <map>
#include <memory>
#include <string>
#include <typeindex>
#include <typeinfo>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/parser_index.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serializer_index.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

class SerializationRegistry {
 public:
  class Builder {
   public:
    // Neither movable nor copyable.
    Builder(const Builder& other) = delete;
    Builder& operator=(const Builder& other) = delete;

    // Creates initially empty serialization registry builder.
    Builder() = default;
    // Creates serialization registry builder by initially copying entries from
    // `registry`.
    explicit Builder(const SerializationRegistry& registry);

    // Registers parameters `parser`. Returns an error if a different parameters
    // parser has already been registered.
    util::Status RegisterParametersParser(ParametersParser* parser);

    // Registers parameters `serializer`. Returns an error if a different
    // parameters serializer has already been registered.
    util::Status RegisterParametersSerializer(ParametersSerializer* serializer);

    // Registers key `parser`. Returns an error if a different key parser has
    // already been registered.
    util::Status RegisterKeyParser(KeyParser* parser);

    // Registers key `serializer`. Returns an error if a different key
    // serializer has already been registered.
    util::Status RegisterKeySerializer(KeySerializer* serializer);

    // Creates serialization registry from this builder.
    SerializationRegistry Build();

   private:
    Builder(const absl::flat_hash_map<ParserIndex, ParametersParser*>&
                parameters_parsers,
            const absl::flat_hash_map<SerializerIndex, ParametersSerializer*>&
                parameters_serializers,
            const absl::flat_hash_map<ParserIndex, KeyParser*> key_parsers,
            const absl::flat_hash_map<SerializerIndex, KeySerializer*>
                key_serializers)
        : parameters_parsers_(parameters_parsers),
          parameters_serializers_(parameters_serializers),
          key_parsers_(key_parsers),
          key_serializers_(key_serializers) {}

    absl::flat_hash_map<ParserIndex, ParametersParser*> parameters_parsers_;
    absl::flat_hash_map<SerializerIndex, ParametersSerializer*>
        parameters_serializers_;
    absl::flat_hash_map<ParserIndex, KeyParser*> key_parsers_;
    absl::flat_hash_map<SerializerIndex, KeySerializer*> key_serializers_;
  };

  // Movable and copyable.
  SerializationRegistry(SerializationRegistry&& other) = default;
  SerializationRegistry& operator=(SerializationRegistry&& other) = default;
  SerializationRegistry(const SerializationRegistry& other) = default;
  SerializationRegistry& operator=(const SerializationRegistry& other) =
      default;

  // Creates empty serialization registry.
  SerializationRegistry() = default;

  // Parses `serialization` into a `Parameters` instance.
  util::StatusOr<std::unique_ptr<Parameters>> ParseParameters(
      const Serialization& serialization) const;

  // Serializes `parameters` into a `Serialization` instance.
  template <typename SerializationT>
  util::StatusOr<std::unique_ptr<Serialization>> SerializeParameters(
      const Parameters& parameters) const {
    SerializerIndex index = SerializerIndex::Create<SerializationT>(parameters);
    auto it = parameters_serializers_.find(index);
    if (it == parameters_serializers_.end()) {
      return util::Status(
          absl::StatusCode::kNotFound,
          absl::StrFormat(
              "No parameters serializer found for parameters type %s",
              typeid(parameters).name()));
    }

    return parameters_serializers_.at(index)->SerializeParameters(parameters);
  }

  // Parses `serialization` into a `Key` instance.
  util::StatusOr<std::unique_ptr<Key>> ParseKey(
      const Serialization& serialization) const;

  // Serializes `parameters` into a `Serialization` instance.
  template <typename SerializationT>
  util::StatusOr<std::unique_ptr<Serialization>> SerializeKey(
      const Key& key) const {
    SerializerIndex index = SerializerIndex::Create<SerializationT>(key);
    auto it = key_serializers_.find(index);
    if (it == key_serializers_.end()) {
      return util::Status(
          absl::StatusCode::kNotFound,
          absl::StrFormat("No key serializer found for key type %s",
                          typeid(key).name()));
    }

    return key_serializers_.at(index)->SerializeKey(
        key, InsecureSecretKeyAccess::Get());
  }

 private:
  SerializationRegistry(
      const absl::flat_hash_map<ParserIndex, ParametersParser*>&
          parameters_parsers,
      const absl::flat_hash_map<SerializerIndex, ParametersSerializer*>&
          parameters_serializers,
      const absl::flat_hash_map<ParserIndex, KeyParser*> key_parsers,
      const absl::flat_hash_map<SerializerIndex, KeySerializer*>
          key_serializers)
      : parameters_parsers_(parameters_parsers),
        parameters_serializers_(parameters_serializers),
        key_parsers_(key_parsers),
        key_serializers_(key_serializers) {}

  absl::flat_hash_map<ParserIndex, ParametersParser*> parameters_parsers_;
  absl::flat_hash_map<SerializerIndex, ParametersSerializer*>
      parameters_serializers_;
  absl::flat_hash_map<ParserIndex, KeyParser*> key_parsers_;
  absl::flat_hash_map<SerializerIndex, KeySerializer*> key_serializers_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_SERIALIZATION_REGISTRY_H_
