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

#include "tink/internal/proto_key_serialization.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/util.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

util::StatusOr<ProtoKeySerialization> ProtoKeySerialization::Create(
    absl::string_view type_url, RestrictedData serialized_key,
    KeyData::KeyMaterialType key_material_type,
    OutputPrefixType output_prefix_type, absl::optional<int> id_requirement) {
  if (!IsPrintableAscii(type_url)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Non-printable ASCII character in type URL.");
  }
  if (output_prefix_type == OutputPrefixType::RAW &&
      id_requirement.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Keys with a RAW output prefix type should not have an "
                        "ID requirement.");
  }
  if (output_prefix_type != OutputPrefixType::RAW &&
      !id_requirement.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Keys without a RAW output prefix type should have an ID requirement.");
  }
  return ProtoKeySerialization(type_url, type_url, std::move(serialized_key),
                               key_material_type, output_prefix_type,
                               id_requirement);
}

bool ProtoKeySerialization::EqualsWithPotentialFalseNegatives(
    const ProtoKeySerialization& other) const {
  if (type_url_ != other.type_url_) return false;
  if (object_identifier_ != other.object_identifier_) return false;
  if (key_material_type_ != other.key_material_type_) return false;
  if (output_prefix_type_ != other.output_prefix_type_) return false;
  if (id_requirement_ != other.id_requirement_) return false;
  // RestrictedData::operator== is a constant-time comparison.
  return serialized_key_ == other.serialized_key_;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
