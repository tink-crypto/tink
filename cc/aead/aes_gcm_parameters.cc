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

#include "tink/aead/aes_gcm_parameters.h"

#include <set>

#include "absl/strings/str_cat.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

AesGcmParameters::Builder& AesGcmParameters::Builder::SetKeySizeInBytes(
    int key_size) {
  key_size_in_bytes_ = key_size;
  return *this;
}

AesGcmParameters::Builder& AesGcmParameters::Builder::SetIvSizeInBytes(
    int iv_size) {
  iv_size_in_bytes_ = iv_size;
  return *this;
}

AesGcmParameters::Builder& AesGcmParameters::Builder::SetTagSizeInBytes(
    int tag_size) {
  tag_size_in_bytes_ = tag_size;
  return *this;
}

AesGcmParameters::Builder& AesGcmParameters::Builder::SetVariant(
    Variant variant) {
  variant_ = variant;
  return *this;
}

util::StatusOr<AesGcmParameters> AesGcmParameters::Builder::Build() {
  if (key_size_in_bytes_ != 16 && key_size_in_bytes_ != 24 &&
      key_size_in_bytes_ != 32) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Key size should be 16, 24, or 32 bytes, got ",
                     key_size_in_bytes_, " bytes."));
  }
  if (iv_size_in_bytes_ <= 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("IV size should be positive, got ",
                                     iv_size_in_bytes_, " bytes."));
  }
  if (tag_size_in_bytes_ < 12 || tag_size_in_bytes_ > 16) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Tag size should be between 12 and 16 bytes, got ",
                     tag_size_in_bytes_, " bytes."));
  }
  static const std::set<Variant>* supported_variants = new std::set<Variant>(
      {Variant::kTink, Variant::kCrunchy, Variant::kNoPrefix});
  if (supported_variants->find(variant_) == supported_variants->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create AES-GCM parameters with unknown variant.");
  }
  return AesGcmParameters(key_size_in_bytes_, iv_size_in_bytes_,
                          tag_size_in_bytes_, variant_);
}

bool AesGcmParameters::operator==(const Parameters& other) const {
  const AesGcmParameters* that = dynamic_cast<const AesGcmParameters*>(&other);
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
