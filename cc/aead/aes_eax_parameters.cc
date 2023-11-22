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

#include "tink/aead/aes_eax_parameters.h"

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

AesEaxParameters::Builder& AesEaxParameters::Builder::SetKeySizeInBytes(
    int key_size) {
  key_size_in_bytes_ = key_size;
  return *this;
}

AesEaxParameters::Builder& AesEaxParameters::Builder::SetIvSizeInBytes(
    int iv_size) {
  iv_size_in_bytes_ = iv_size;
  return *this;
}

AesEaxParameters::Builder& AesEaxParameters::Builder::SetTagSizeInBytes(
    int tag_size) {
  tag_size_in_bytes_ = tag_size;
  return *this;
}

AesEaxParameters::Builder& AesEaxParameters::Builder::SetVariant(
    Variant variant) {
  variant_ = variant;
  return *this;
}

util::StatusOr<AesEaxParameters> AesEaxParameters::Builder::Build() {
  if (!key_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Key size is not set.");
  }

  if (!iv_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "IV size is not set.");
  }

  if (!tag_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Tag size is not set.");
  }

  if (!variant_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Variant is not set.");
  }

  if (*key_size_in_bytes_ != 16 && *key_size_in_bytes_ != 24 &&
      *key_size_in_bytes_ != 32) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Key size should be 16, 24, or 32 bytes, got ",
                     *key_size_in_bytes_, " bytes."));
  }
  if (*iv_size_in_bytes_ != 12 && *iv_size_in_bytes_ != 16) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("IV size should be 12 or 16 bytes, got ",
                                     *iv_size_in_bytes_, " bytes."));
  }
  if (*tag_size_in_bytes_ < 0 || *tag_size_in_bytes_ > 16) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Tag size should be positive and at most 16 bytes, got ",
                     *tag_size_in_bytes_, " bytes."));
  }

  static const auto* kSupportedVariants = new absl::flat_hash_set<Variant>(
      {Variant::kTink, Variant::kCrunchy, Variant::kNoPrefix});
  if (!kSupportedVariants->contains(*variant_)) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create AES-Eax parameters with unknown variant.");
  }
  return AesEaxParameters(*key_size_in_bytes_, *iv_size_in_bytes_,
                          *tag_size_in_bytes_, *variant_);
}

bool AesEaxParameters::operator==(const Parameters& other) const {
  const AesEaxParameters* that = dynamic_cast<const AesEaxParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (key_size_in_bytes_ != that->key_size_in_bytes_) {
    return false;
  }
  if (iv_size_in_bytes_ != that->iv_size_in_bytes_) {
    return false;
  }
  if (tag_size_in_bytes_ != that->tag_size_in_bytes_) {
    return false;
  }
  if (variant_ != that->variant_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
