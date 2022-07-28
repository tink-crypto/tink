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

// static
pb::SphincsHashType EnumsPqcrypto::SubtleToProto(subtle::SphincsHashType type) {
  switch (type) {
    case subtle::SphincsHashType::HARAKA:
      return pb::SphincsHashType::HARAKA;
    case subtle::SphincsHashType::SHA256:
      return pb::SphincsHashType::SHA256;
    case subtle::SphincsHashType::SHAKE256:
      return pb::SphincsHashType::SHAKE256;
    default:
      return pb::SphincsHashType::HASH_TYPE_UNSPECIFIED;
  }
}

// static
subtle::SphincsHashType EnumsPqcrypto::ProtoToSubtle(pb::SphincsHashType type) {
  switch (type) {
    case pb::SphincsHashType::HARAKA:
      return subtle::SphincsHashType::HARAKA;
    case pb::SphincsHashType::SHA256:
      return subtle::SphincsHashType::SHA256;
    case pb::SphincsHashType::SHAKE256:
      return subtle::SphincsHashType::SHAKE256;
    default:
      return subtle::SphincsHashType::HASH_TYPE_UNSPECIFIED;
  }
}

// static
pb::SphincsVariant EnumsPqcrypto::SubtleToProto(
    subtle::SphincsVariant variant) {
  switch (variant) {
    case subtle::SphincsVariant::ROBUST:
      return pb::SphincsVariant::ROBUST;
    case subtle::SphincsVariant::SIMPLE:
      return pb::SphincsVariant::SIMPLE;
    default:
      return pb::SphincsVariant::VARIANT_UNSPECIFIED;
  }
}

// static
subtle::SphincsVariant EnumsPqcrypto::ProtoToSubtle(
    pb::SphincsVariant variant) {
  switch (variant) {
    case pb::SphincsVariant::ROBUST:
      return subtle::SphincsVariant::ROBUST;
    case pb::SphincsVariant::SIMPLE:
      return subtle::SphincsVariant::SIMPLE;
    default:
      return subtle::SphincsVariant::VARIANT_UNSPECIFIED;
  }
}

// static
pb::SphincsSignatureType EnumsPqcrypto::SubtleToProto(
    subtle::SphincsSignatureType type) {
  switch (type) {
    case subtle::SphincsSignatureType::FAST_SIGNING:
      return pb::SphincsSignatureType::FAST_SIGNING;
    case subtle::SphincsSignatureType::SMALL_SIGNATURE:
      return pb::SphincsSignatureType::SMALL_SIGNATURE;
    default:
      return pb::SphincsSignatureType::SIG_TYPE_UNSPECIFIED;
  }
}

// static
subtle::SphincsSignatureType EnumsPqcrypto::ProtoToSubtle(
    pb::SphincsSignatureType type) {
  switch (type) {
    case pb::SphincsSignatureType::FAST_SIGNING:
      return subtle::SphincsSignatureType::FAST_SIGNING;
    case pb::SphincsSignatureType::SMALL_SIGNATURE:
      return subtle::SphincsSignatureType::SMALL_SIGNATURE;
    default:
      return subtle::SphincsSignatureType::SIG_TYPE_UNSPECIFIED;
  }
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
