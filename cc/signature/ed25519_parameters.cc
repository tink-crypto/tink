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

#include "tink/signature/ed25519_parameters.h"

#include <set>

#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<Ed25519Parameters> Ed25519Parameters::Create(Variant variant) {
  static const std::set<Variant>* supported_variants =
      new std::set<Variant>({Variant::kTink, Variant::kCrunchy,
                             Variant::kLegacy, Variant::kNoPrefix});
  if (supported_variants->find(variant) == supported_variants->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create Ed25519 parameters with unknown variant.");
  }
  return Ed25519Parameters(variant);
}

bool Ed25519Parameters::operator==(const Parameters& other) const {
  const Ed25519Parameters* that =
      dynamic_cast<const Ed25519Parameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return variant_ == that->variant_;
}

}  // namespace tink
}  // namespace crypto
