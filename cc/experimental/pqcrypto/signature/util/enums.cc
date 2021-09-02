// Copyright 2021 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/signature/util/enums.h"

namespace crypto {
namespace tink {
namespace util {

namespace pb = google::crypto::tink;

// static
pb::DilithiumSeedExpansion EnumsPqcrypto::SubtleToProto(
    subtle::DilithiumSeedExpansion expansion) {
  switch (expansion) {
    case subtle::DilithiumSeedExpansion::SEED_EXPANSION_SHAKE:
      return pb::DilithiumSeedExpansion::SEED_EXPANSION_SHAKE;
    case subtle::DilithiumSeedExpansion::SEED_EXPANSION_AES:
      return pb::DilithiumSeedExpansion::SEED_EXPANSION_AES;
    default:
      return pb::DilithiumSeedExpansion::SEED_EXPANSION_UNKNOWN;
  }
}

// static
subtle::DilithiumSeedExpansion EnumsPqcrypto::ProtoToSubtle(
    pb::DilithiumSeedExpansion expansion) {
  switch (expansion) {
    case pb::DilithiumSeedExpansion::SEED_EXPANSION_SHAKE:
      return subtle::DilithiumSeedExpansion::SEED_EXPANSION_SHAKE;
    case pb::DilithiumSeedExpansion::SEED_EXPANSION_AES:
      return subtle::DilithiumSeedExpansion::SEED_EXPANSION_AES;
    default:
      return subtle::DilithiumSeedExpansion::SEED_EXPANSION_UNKNOWN;
  }
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
