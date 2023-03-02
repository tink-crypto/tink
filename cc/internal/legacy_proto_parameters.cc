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

#include "tink/internal/legacy_proto_parameters.h"

#include "tink/internal/proto_parameters_serialization.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {
namespace internal {

bool LegacyProtoParameters::operator==(const Parameters& other) const {
  const LegacyProtoParameters* that =
      dynamic_cast<const LegacyProtoParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return serialization_.EqualsWithPotentialFalseNegatives(that->serialization_);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
