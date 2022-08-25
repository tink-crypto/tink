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

#include "tink/mac/aes_cmac_parameters.h"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <ostream>
#include <set>

#include "tink/crypto_format.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<AesCmacParameters> AesCmacParameters::Create(
    int key_size_in_bytes, int cryptographic_tag_size_in_bytes,
    Variant variant) {
  if (key_size_in_bytes != 16 && key_size_in_bytes != 32) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Key size should be either 16 or 32 bytes, got ",
                     key_size_in_bytes, " bytes."));
  }
  if (cryptographic_tag_size_in_bytes < 10) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Tag size should be at least 10 bytes, got ",
                     cryptographic_tag_size_in_bytes, " bytes."));
  }
  if (cryptographic_tag_size_in_bytes > 16) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Tag size should not exceed 16 bytes, got ",
                     cryptographic_tag_size_in_bytes, " bytes."));
  }
  static const std::set<Variant>* supported_variants =
      new std::set<Variant>({Variant::kTink, Variant::kCrunchy,
                             Variant::kLegacy, Variant::kNoPrefix});
  if (supported_variants->find(variant) == supported_variants->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create AES-CMAC parameters with unknown variant.");
  }
  return AesCmacParameters(key_size_in_bytes, cryptographic_tag_size_in_bytes,
                           variant);
}

int AesCmacParameters::TotalTagSizeInBytes() const {
  switch (variant_) {
    case Variant::kTink:
    case Variant::kCrunchy:
    case Variant::kLegacy:
      return CryptographicTagSizeInBytes() + CryptoFormat::kNonRawPrefixSize;
    case Variant::kNoPrefix:
      return CryptographicTagSizeInBytes();
    default:
      // Parameters objects with unknown variants should never be created.
      std::cerr << "AES-CMAC parameters has an unknown variant." << std::endl;
      std::exit(1);
  }
}

bool AesCmacParameters::operator==(const Parameters& other) const {
  const AesCmacParameters* that =
      dynamic_cast<const AesCmacParameters*>(&other);
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
  if (variant_ != that->variant_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
