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

#include "tink/mac/aes_cmac_key.h"

#include <memory>
#include <string>

#include "absl/base/attributes.h"
#include "absl/strings/escaping.h"
#include "absl/types/optional.h"
#include "absl/strings/str_format.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/restricted_data.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<AesCmacKey> AesCmacKey::Create(
    AesCmacParameters parameters, RestrictedData aes_key_bytes,
    absl::optional<int> id_requirement) {
  if (aes_key_bytes.size() != 32) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid key size for AES-CMAC: ", aes_key_bytes.size()));
  }
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
  return AesCmacKey(parameters, aes_key_bytes, id_requirement);
}

util::StatusOr<std::string> AesCmacKey::GetOutputPrefix() const {
  switch (parameters_.GetVariant()) {
    case AesCmacParameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case AesCmacParameters::Variant::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;
    case AesCmacParameters::Variant::kCrunchy:
      return absl::StrCat(absl::HexStringToBytes("00"),
                          subtle::BigEndian32(*id_requirement_));
    case AesCmacParameters::Variant::kTink:
      return absl::StrCat(absl::HexStringToBytes("01"),
                          subtle::BigEndian32(*id_requirement_));
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid variant: ", parameters_.GetVariant()));
  }
}

bool AesCmacKey::operator==(const Key& other) const {
  const AesCmacKey* that = dynamic_cast<const AesCmacKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  return aes_key_bytes_ == that->aes_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
