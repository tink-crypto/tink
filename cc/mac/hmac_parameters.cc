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

#include "tink/mac/hmac_parameters.h"

#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <ostream>
#include <set>

#include "absl/log/log.h"
#include "tink/crypto_format.h"
#include "tink/internal/util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::Status ValidateTagSizeBytes(int cryptographic_tag_size_in_bytes,
                                  HmacParameters::HashType hash_type) {
  if (cryptographic_tag_size_in_bytes < 10) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Tag size should be at least 10 bytes, got ",
                     cryptographic_tag_size_in_bytes, " bytes."));
  }
  std::map<HmacParameters::HashType, uint32_t> max_tag_size = {
      {HmacParameters::HashType::kSha1, 20},
      {HmacParameters::HashType::kSha224, 28},
      {HmacParameters::HashType::kSha256, 32},
      {HmacParameters::HashType::kSha384, 48},
      {HmacParameters::HashType::kSha512, 64}};
  if (max_tag_size.find(hash_type) == max_tag_size.end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Cannot create HMAC parameters with given hash type. ",
                     hash_type, " not supported."));
  }
  if (cryptographic_tag_size_in_bytes > max_tag_size[hash_type]) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Tag size is too big for given ", hash_type, " , got ",
                     cryptographic_tag_size_in_bytes, " bytes."));
  }
  return util::OkStatus();
}

}  // namespace

util::StatusOr<HmacParameters> HmacParameters::Create(
    int key_size_in_bytes, int cryptographic_tag_size_in_bytes,
    HashType hash_type, Variant variant) {
  if (key_size_in_bytes < 16) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Key size must be at least 16 bytes, got ",
                                     key_size_in_bytes, " bytes."));
  }
  util::Status status =
      ValidateTagSizeBytes(cryptographic_tag_size_in_bytes, hash_type);
  if (!status.ok()) return status;
  static const std::set<Variant>* supported_variants =
      new std::set<Variant>({Variant::kTink, Variant::kCrunchy,
                             Variant::kLegacy, Variant::kNoPrefix});
  if (supported_variants->find(variant) == supported_variants->end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create HMAC parameters with unknown variant.");
  }
  return HmacParameters(key_size_in_bytes, cryptographic_tag_size_in_bytes,
                        hash_type, variant);
}

int HmacParameters::TotalTagSizeInBytes() const {
  switch (variant_) {
    case Variant::kTink:
    case Variant::kCrunchy:
    case Variant::kLegacy:
      return CryptographicTagSizeInBytes() + CryptoFormat::kNonRawPrefixSize;
    case Variant::kNoPrefix:
      return CryptographicTagSizeInBytes();
    default:
      // Parameters objects with unknown variants should never be created.
      internal::LogFatal("HMAC parameters has an unknown variant.");
  }
}

bool HmacParameters::operator==(const Parameters& other) const {
  const HmacParameters* that = dynamic_cast<const HmacParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (key_size_in_bytes_ != that->key_size_in_bytes_) {
    return false;
  }
  if (cryptographic_tag_size_in_bytes_ !=
      that->cryptographic_tag_size_in_bytes_) {
    return false;
  }
  if (hash_type_ != that->hash_type_) {
    return false;
  }
  if (variant_ != that->variant_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
