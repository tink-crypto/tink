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

#include "tink/internal/serialization_registry.h"

#include <memory>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_format.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/parser_index.h"
#include "tink/internal/serializer_index.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

SerializationRegistry::Builder::Builder(const SerializationRegistry& registry)
    : Builder(registry.parameters_parsers_, registry.parameters_serializers_,
              registry.key_parsers_, registry.key_serializers_) {}

util::Status SerializationRegistry::Builder::RegisterParametersParser(
    ParametersParser* parser) {
  ParserIndex index = parser->Index();
  auto it = parameters_parsers_.find(index);
  if (it != parameters_parsers_.end()) {
    if (parameters_parsers_[index] != parser) {
      return util::Status(absl::StatusCode::kAlreadyExists,
                          "Attempted to update existing parameters parser.");
    }
  }
  parameters_parsers_.insert({parser->Index(), parser});
  return util::OkStatus();
}

util::Status SerializationRegistry::Builder::RegisterParametersSerializer(
    ParametersSerializer* serializer) {
  SerializerIndex index = serializer->Index();
  auto it = parameters_serializers_.find(index);
  if (it != parameters_serializers_.end()) {
    if (parameters_serializers_[index] != serializer) {
      return util::Status(
          absl::StatusCode::kAlreadyExists,
          "Attempted to update existing parameters serializer.");
    }
  }
  parameters_serializers_.insert({serializer->Index(), serializer});
  return util::OkStatus();
}

util::Status SerializationRegistry::Builder::RegisterKeyParser(
    KeyParser* parser) {
  ParserIndex index = parser->Index();
  auto it = key_parsers_.find(index);
  if (it != key_parsers_.end()) {
    if (key_parsers_[index] != parser) {
      return util::Status(absl::StatusCode::kAlreadyExists,
                          "Attempted to update existing key parser.");
    }
  }
  key_parsers_.insert({parser->Index(), parser});
  return util::OkStatus();
}

util::Status SerializationRegistry::Builder::RegisterKeySerializer(
    KeySerializer* serializer) {
  SerializerIndex index = serializer->Index();
  auto it = key_serializers_.find(index);
  if (it != key_serializers_.end()) {
    if (key_serializers_[index] != serializer) {
      return util::Status(absl::StatusCode::kAlreadyExists,
                          "Attempted to update existing key serializer.");
    }
  }
  key_serializers_.insert({serializer->Index(), serializer});
  return util::OkStatus();
}

SerializationRegistry SerializationRegistry::Builder::Build() {
  return SerializationRegistry(parameters_parsers_, parameters_serializers_,
                               key_parsers_, key_serializers_);
}

util::StatusOr<std::unique_ptr<Parameters>>
SerializationRegistry::ParseParameters(
    const Serialization& serialization) const {
  ParserIndex index = ParserIndex::Create(serialization);
  auto it = parameters_parsers_.find(index);
  if (it == parameters_parsers_.end()) {
    return util::Status(
        absl::StatusCode::kNotFound,
        absl::StrFormat("No parameters parser found for parameters type %s",
                        typeid(serialization).name()));
  }

  return parameters_parsers_.at(index)->ParseParameters(serialization);
}

util::StatusOr<std::unique_ptr<Key>> SerializationRegistry::ParseKey(
    const Serialization& serialization) const {
  ParserIndex index = ParserIndex::Create(serialization);
  auto it = key_parsers_.find(index);
  if (it == key_parsers_.end()) {
    return util::Status(
        absl::StatusCode::kNotFound,
        absl::StrFormat("No key parser found for serialization type %s",
                        typeid(serialization).name()));
  }

  return key_parsers_.at(index)->ParseKey(serialization,
                                          InsecureSecretKeyAccess::Get());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
