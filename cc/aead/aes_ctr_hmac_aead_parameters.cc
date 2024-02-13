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

#include "tink/aead/aes_ctr_hmac_aead_parameters.h"

#include <cstdint>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

AesCtrHmacAeadParameters::Builder&
AesCtrHmacAeadParameters::Builder::SetAesKeySizeInBytes(int aes_key_size) {
  aes_key_size_in_bytes_ = aes_key_size;
  return *this;
}

AesCtrHmacAeadParameters::Builder&
AesCtrHmacAeadParameters::Builder::SetHmacKeySizeInBytes(int hmac_key_size) {
  hmac_key_size_in_bytes_ = hmac_key_size;
  return *this;
}

AesCtrHmacAeadParameters::Builder&
AesCtrHmacAeadParameters::Builder::SetIvSizeInBytes(int iv_size) {
  iv_size_in_bytes_ = iv_size;
  return *this;
}

AesCtrHmacAeadParameters::Builder&
AesCtrHmacAeadParameters::Builder::SetTagSizeInBytes(int tag_size) {
  tag_size_in_bytes_ = tag_size;
  return *this;
}

AesCtrHmacAeadParameters::Builder&
AesCtrHmacAeadParameters::Builder::SetHashType(HashType hash_type) {
  hash_type_ = hash_type;
  return *this;
}

AesCtrHmacAeadParameters::Builder&
AesCtrHmacAeadParameters::Builder::SetVariant(Variant variant) {
  variant_ = variant;
  return *this;
}

util::StatusOr<AesCtrHmacAeadParameters>
AesCtrHmacAeadParameters::Builder::Build() {
  if (!aes_key_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "AES key size is not set.");
  }

  if (!hmac_key_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "HMAC key size is not set.");
  }

  if (!iv_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "IV size is not set.");
  }

  if (!tag_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Tag size is not set.");
  }

  if (!hash_type_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Hash type is not set.");
  }

  if (!variant_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Variant is not set.");
  }
  if (*aes_key_size_in_bytes_ != 16 && *aes_key_size_in_bytes_ != 24 &&
      *aes_key_size_in_bytes_ != 32) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("AES key size should be 16, 24, or 32 bytes, got ",
                     *aes_key_size_in_bytes_, " bytes."));
  }
  if (*hmac_key_size_in_bytes_ < 16) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("HMAC key size should have at least 16 bytes, got ",
                     *hmac_key_size_in_bytes_, " bytes."));
  }
  if (*iv_size_in_bytes_ < 12 || *iv_size_in_bytes_ > 16) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("IV size should be betwwen 12 and 16 bytes, got ",
                     *iv_size_in_bytes_, " bytes."));
  }
  if (*tag_size_in_bytes_ < 10) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Tag size should have at least 10 bytes, got ",
                     *tag_size_in_bytes_, " bytes."));
  }
  // The maximum allowed value of the tag size is limited by the hash type used.
  static const absl::flat_hash_map<HashType, uint32_t>* kMaxTagSizes =
      new absl::flat_hash_map<HashType, uint32_t>{{HashType::kSha1, 20},
                                                  {HashType::kSha224, 28},
                                                  {HashType::kSha256, 32},
                                                  {HashType::kSha384, 48},
                                                  {HashType::kSha512, 64}};
  if (kMaxTagSizes->find(*hash_type_) == kMaxTagSizes->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create AesCtrHmacAeadParameters with unknown hash type.");
  } else {
    if (*tag_size_in_bytes_ > kMaxTagSizes->at(*hash_type_)) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Tag size ", *tag_size_in_bytes_,
                                       " is too big for given hash type."));
    }
  }
  static constexpr Variant kSupportedVariants[] = {
      Variant::kTink, Variant::kCrunchy, Variant::kNoPrefix};
  if (!absl::c_linear_search(kSupportedVariants, *variant_)) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create AesCtrHmacAeadParameters with unknown Variant.");
  }
  return AesCtrHmacAeadParameters(*aes_key_size_in_bytes_,
                                  *hmac_key_size_in_bytes_, *iv_size_in_bytes_,
                                  *tag_size_in_bytes_, *hash_type_, *variant_);
}

bool AesCtrHmacAeadParameters::operator==(const Parameters& other) const {
  const AesCtrHmacAeadParameters* that =
      dynamic_cast<const AesCtrHmacAeadParameters*>(&other);
  if (that == nullptr) return false;
  return aes_key_size_in_bytes_ == that->aes_key_size_in_bytes_ &&
         hmac_key_size_in_bytes_ == that->hmac_key_size_in_bytes_ &&
         iv_size_in_bytes_ == that->iv_size_in_bytes_ &&
         tag_size_in_bytes_ == that->tag_size_in_bytes_ &&
         hash_type_ == that->hash_type_ && variant_ == that->variant_;
}

}  // namespace tink
}  // namespace crypto
