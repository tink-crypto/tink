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

#include "tink/daead/aes_siv_parameters.h"

#include <set>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<AesSivParameters> AesSivParameters::Create(int key_size_in_bytes,
                                                          Variant variant) {
  if (key_size_in_bytes != 32 && key_size_in_bytes != 48 &&
      key_size_in_bytes != 64) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Key size should be 32, 48, or 64 bytes, got ",
                     key_size_in_bytes, " bytes."));
  }
  static const std::set<Variant>* supported_variants = new std::set<Variant>(
      {Variant::kTink, Variant::kCrunchy, Variant::kNoPrefix});
  if (supported_variants->find(variant) == supported_variants->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create AES-SIV parameters with unknown variant.");
  }
  return AesSivParameters(key_size_in_bytes, variant);
}

bool AesSivParameters::operator==(const Parameters& other) const {
  const AesSivParameters* that = dynamic_cast<const AesSivParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (key_size_in_bytes_ != that->key_size_in_bytes_) {
    return false;
  }
  if (variant_ != that->variant_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
