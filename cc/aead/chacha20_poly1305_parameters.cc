// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/chacha20_poly1305_parameters.h"

#include <set>

#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<ChaCha20Poly1305Parameters> ChaCha20Poly1305Parameters::Create(
    Variant variant) {
  static const std::set<Variant>* kSupportedVariants = new std::set<Variant>(
      {Variant::kTink, Variant::kCrunchy, Variant::kNoPrefix});
  if (kSupportedVariants->find(variant) == kSupportedVariants->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create ChaCha20-Poly1305 parameters with unknown variant.");
  }
  return ChaCha20Poly1305Parameters(variant);
}

bool ChaCha20Poly1305Parameters::operator==(const Parameters& other) const {
  const ChaCha20Poly1305Parameters* that =
      dynamic_cast<const ChaCha20Poly1305Parameters*>(&other);
  return that != nullptr && variant_ == that->variant_;
}

}  // namespace tink
}  // namespace crypto
