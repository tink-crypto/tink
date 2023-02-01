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

#ifndef TINK_INTERNAL_PARAMETERS_SERIALIZER_H_
#define TINK_INTERNAL_PARAMETERS_SERIALIZER_H_

#include <functional>
#include <memory>
#include <string>
#include <typeindex>

#include "absl/strings/string_view.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serializer_index.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Non-template base class that can be used with internal registry map.
class ParametersSerializer {
 public:
  // Returns the serialization of `parameters`.
  virtual util::StatusOr<std::unique_ptr<Serialization>> SerializeParameters(
      const Parameters& parameters) const = 0;

  // Returns the object identifier for this serialization, which is only valid
  // for the lifetime of this object.
  //
  // The object identifier is a unique identifier per registry for this object
  // (in the standard proto serialization, it is the type URL). In other words,
  // when registering a `ParametersSerializer`, the registry will invoke this to
  // get the handled object identifier. In order to serialize an object of
  // `ParametersT`, the registry will then obtain the object identifier of
  // this serialization object, and call the serializer corresponding to this
  // object.
  virtual absl::string_view ObjectIdentifier() const = 0;

  // Returns an index that can be used to look up the `ParametersSerializer`
  // object registered for the `ParametersT` type in a registry.
  virtual SerializerIndex Index() const = 0;

  virtual ~ParametersSerializer() = default;
};

// Serializes `ParametersT` objects into `SerializationT` objects.
template <typename ParametersT, typename SerializationT>
class ParametersSerializerImpl : public ParametersSerializer {
 public:
  explicit ParametersSerializerImpl(
      absl::string_view object_identifier,
      const std::function<util::StatusOr<SerializationT>(ParametersT)>&
          function)
      : object_identifier_(object_identifier), function_(function) {}

  util::StatusOr<std::unique_ptr<Serialization>> SerializeParameters(
      const Parameters& parameters) const override {
    const ParametersT* pt = dynamic_cast<const ParametersT*>(&parameters);
    if (pt == nullptr) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Invalid parameters type for this parameters serializer.");
    }
    util::StatusOr<SerializationT> serialization = function_(*pt);
    if (!serialization.ok()) return serialization.status();
    return {absl::make_unique<SerializationT>(std::move(*serialization))};
  }

  absl::string_view ObjectIdentifier() const override {
    return object_identifier_;
  }

  SerializerIndex Index() const override {
    return SerializerIndex::Create<ParametersT, SerializationT>();
  }

 private:
  std::string object_identifier_;
  std::function<util::StatusOr<SerializationT>(ParametersT)> function_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PARAMETERS_SERIALIZER_H_
