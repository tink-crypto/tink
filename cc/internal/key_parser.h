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

#ifndef TINK_INTERNAL_KEY_PARSER_H_
#define TINK_INTERNAL_KEY_PARSER_H_

#include <functional>
#include <string>
#include <typeindex>

#include "absl/functional/function_ref.h"
#include "absl/strings/string_view.h"
#include "tink/internal/parser_index.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Non-template base class that can be used with internal registry map.
class KeyParserBase {
 public:
  // Returns the object identifier for `SerializationT`, which is only valid
  // for the lifetime of this object.
  //
  // The object identifier is a unique identifier per registry for this object
  // (in the standard proto serialization, it is the type URL). In other words,
  // when registering a `KeyParser`, the registry will invoke this to get
  // the handled object identifier. In order to parse an object of
  // `SerializationT`, the registry will then obtain the object identifier of
  // this serialization object, and call the parser corresponding to this
  // object.
  virtual absl::string_view ObjectIdentifier() const = 0;

  // Returns an index that can be used to look up the `KeyParser`
  // object registered for the `KeyT` type in a registry.
  virtual ParserIndex Index() const = 0;

  virtual ~KeyParserBase() = default;
};

// Parses `SerializationT` objects into `KeyT` objects.
template <typename SerializationT, typename KeyT>
class KeyParser : public KeyParserBase {
 public:
  // Creates a key parser with `object_identifier` and parsing `function`. The
  // referenced `function` should outlive the created key parser object.
  explicit KeyParser(absl::string_view object_identifier,
                     absl::FunctionRef<util::StatusOr<KeyT>(
                         SerializationT, SecretKeyAccessToken)>
                         function)
      : object_identifier_(object_identifier), function_(function) {}

  // Parses a `serialization` into a key.
  //
  // This function is usually called with a `SerializationT` matching the
  // value returned by `ObjectIdentifier()`. However, implementations should
  // check that this is the case.
  util::StatusOr<KeyT> ParseKey(SerializationT serialization,
                                SecretKeyAccessToken token) const {
    return function_(serialization, token);
  }

  absl::string_view ObjectIdentifier() const override {
    return object_identifier_;
  }

  ParserIndex Index() const override {
    return ParserIndex::Create<SerializationT>(object_identifier_);
  }

 private:
  std::string object_identifier_;
  std::function<util::StatusOr<KeyT>(SerializationT, SecretKeyAccessToken)>
      function_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEY_PARSER_H_
