// Copyright 2024 Google LLC
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

#include "tink/aead/aes_ctr_hmac_aead_key.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::StatusOr<std::string> ComputeOutputPrefix(
    const AesCtrHmacAeadParameters& parameters,
    absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case AesCtrHmacAeadParameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case AesCtrHmacAeadParameters::Variant::kCrunchy:
      if (!id_requirement.has_value()) {
        return util::Status(
            absl::StatusCode::kInvalidArgument,
            "ID requirement must not be empty with kCrunchy or kLegacy");
      }
      return absl::StrCat(absl::HexStringToBytes("00"),
                          subtle::BigEndian32(*id_requirement));
    case AesCtrHmacAeadParameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "ID requirement must not be empty with kTink");
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

AesCtrHmacAeadKey::Builder& AesCtrHmacAeadKey::Builder::SetParameters(
    const AesCtrHmacAeadParameters& parameters) {
  parameters_ = parameters;
  return *this;
}

AesCtrHmacAeadKey::Builder& AesCtrHmacAeadKey::Builder::SetAesKeyBytes(
    const RestrictedData& aes_key_bytes) {
  aes_key_bytes_ = aes_key_bytes;
  return *this;
}

AesCtrHmacAeadKey::Builder& AesCtrHmacAeadKey::Builder::SetHmacKeyBytes(
    const RestrictedData& hmac_key_bytes) {
  hmac_key_bytes_ = hmac_key_bytes;
  return *this;
}

AesCtrHmacAeadKey::Builder& AesCtrHmacAeadKey::Builder::SetIdRequirement(
    absl::optional<int> id_requirement) {
  id_requirement_ = id_requirement;
  return *this;
}

util::StatusOr<AesCtrHmacAeadKey> AesCtrHmacAeadKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!parameters_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the parameters");
  }

  if (!aes_key_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without AES key material");
  }

  if (!hmac_key_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without HMAC key material");
  }

  if (parameters_->GetAesKeySizeInBytes() != aes_key_bytes_->size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "AES key size does not match "
                        "AesCtrHmacAeadParameters::GetAesKeySizeInBytes");
  }

  if (parameters_->GetHmacKeySizeInBytes() != hmac_key_bytes_->size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "HMAC key size does not match "
                        "AesCtrHmacAeadParameters::GetHmacKeySizeInBytes");
  }

  if (parameters_->HasIdRequirement() && !id_requirement_.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters_->HasIdRequirement() && id_requirement_.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }
  util::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(*parameters_, id_requirement_);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }

  return AesCtrHmacAeadKey(*parameters_, *aes_key_bytes_, *hmac_key_bytes_,
                           id_requirement_, *std::move(output_prefix));
}

bool AesCtrHmacAeadKey::operator==(const Key& other) const {
  const AesCtrHmacAeadKey* that =
      dynamic_cast<const AesCtrHmacAeadKey*>(&other);
  if (that == nullptr) return false;
  return GetParameters() == that->GetParameters() &&
         aes_key_bytes_ == that->aes_key_bytes_ &&
         hmac_key_bytes_ == that->hmac_key_bytes_ &&
         id_requirement_ == that->id_requirement_;
}

}  // namespace tink
}  // namespace crypto
