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

#include "tink/signature/ed25519_public_key.h"

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::StatusOr<std::string> ComputeOutputPrefix(
    const Ed25519Parameters& parameters, absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case Ed25519Parameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case Ed25519Parameters::Variant::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;
    case Ed25519Parameters::Variant::kCrunchy:
      if (!id_requirement.has_value()) {
        return util::Status(
            absl::StatusCode::kInvalidArgument,
            "ID requirement must have value with kCrunchy or kLegacy");
      }
      return absl::StrCat(absl::HexStringToBytes("00"),
                          subtle::BigEndian32(*id_requirement));
    case Ed25519Parameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "ID requirement must have value with kTink");
      }
      return absl::StrCat(absl::HexStringToBytes("01"),
                          subtle::BigEndian32(*id_requirement));
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid variant: ", parameters.GetVariant()));
  }
}

}  // namespace

util::StatusOr<Ed25519PublicKey> Ed25519PublicKey::Create(
    const Ed25519Parameters& parameters, absl::string_view public_key_bytes,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  if (parameters.HasIdRequirement() && !id_requirement.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters.HasIdRequirement() && id_requirement.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }
  if (public_key_bytes.size() != 32) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Ed25519 public key length must be 32 bytes.");
  }
  util::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }
  return Ed25519PublicKey(parameters, public_key_bytes, id_requirement,
                          *output_prefix);
}

bool Ed25519PublicKey::operator==(const Key& other) const {
  const Ed25519PublicKey* that = dynamic_cast<const Ed25519PublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  return public_key_bytes_ == that->public_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
