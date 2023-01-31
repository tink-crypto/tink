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

#ifndef TINK_INTERNAL_PARAMETERS_PARSER_H_
#define TINK_INTERNAL_PARAMETERS_PARSER_H_

#include <functional>
#include <string>
#include <typeindex>

#include "absl/strings/string_view.h"
#include "tink/internal/parser_index.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Non-template base class that can be used with internal registry map.
class ParametersParserBase {
 public:
  // Returns the object identifier for `SerializationT`, which is only valid
  // for the lifetime of this object.
  //
  // The object identifier is a unique identifier per registry for this object
  // (in the standard proto serialization, it is the type URL). In other words,
  // when registering a `ParametersParser`, the registry will invoke this to get
  // the handled object identifier. In order to parse an object of
  // `SerializationT`, the registry will then obtain the object identifier of
  // this serialization object, and call the parser corresponding to this
  // object.
  virtual absl::string_view ObjectIdentifier() const = 0;

  // Returns an index that can be used to look up the `ParametersParser`
  // object registered for the `ParametersT` type in a registry.
  virtual ParserIndex Index() const = 0;

  virtual ~ParametersParserBase() = default;
};

// Parses `SerializationT` objects into `ParametersT` objects.
template <typename SerializationT, typename ParametersT>
class ParametersParser : public ParametersParserBase {
 public:
  explicit ParametersParser(
      absl::string_view object_identifier,
      const std::function<util::StatusOr<ParametersT>(SerializationT)>&
          function)
      : object_identifier_(object_identifier), function_(function) {}

  // Parses `serialization` into a parameters object.
  //
  // This function is usually called with a `SerializationT` matching the
  // value returned by `ObjectIdentifier()`. However, implementations should
  // verify that this is the case.
  util::StatusOr<ParametersT> ParseParameters(
      SerializationT serialization) const {
    return function_(serialization);
  }

  absl::string_view ObjectIdentifier() const override {
    return object_identifier_;
  }

  ParserIndex Index() const override {
    return ParserIndex::Create<SerializationT>(object_identifier_);
  }

 private:
  std::string object_identifier_;
  std::function<util::StatusOr<ParametersT>(SerializationT)> function_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PARAMETERS_PARSER_H_
