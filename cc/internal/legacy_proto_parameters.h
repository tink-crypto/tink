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

#ifndef TINK_INTERNAL_LEGACY_PROTO_PARAMETERS_H_
#define TINK_INTERNAL_LEGACY_PROTO_PARAMETERS_H_

#include <utility>

#include "tink/internal/proto_parameters_serialization.h"
#include "tink/parameters.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class LegacyProtoParameters : public Parameters {
 public:
  // Copyable and movable.
  LegacyProtoParameters(const LegacyProtoParameters& other) = default;
  LegacyProtoParameters& operator=(const LegacyProtoParameters& other) =
      default;
  LegacyProtoParameters(LegacyProtoParameters&& other) = default;
  LegacyProtoParameters& operator=(LegacyProtoParameters&& other) = default;

  explicit LegacyProtoParameters(ProtoParametersSerialization serialization)
      : serialization_(std::move(serialization)) {}

  bool HasIdRequirement() const override {
    return serialization_.GetKeyTemplate().output_prefix_type() !=
           google::crypto::tink::OutputPrefixType::RAW;
  }

  bool operator==(const Parameters& other) const override;

  const ProtoParametersSerialization& Serialization() const {
    return serialization_;
  }

 private:
  ProtoParametersSerialization serialization_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_LEGACY_PROTO_PARAMETERS_H_
