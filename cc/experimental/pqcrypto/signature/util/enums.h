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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_UTIL_ENUMS_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_UTIL_ENUMS_H_

#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_key.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_subtle_utils.h"
#include "tink/util/statusor.h"
#include "proto/experimental/pqcrypto/dilithium.pb.h"
#include "proto/experimental/pqcrypto/sphincs.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace util {

// Helpers for translation of pqcrypto enums between protocol buffer enums,
// their string representation, and pqcrypto enums used in subtle.
class EnumsPqcrypto {
 public:
  // DilithiumSeedExpansion.
  static google::crypto::tink::DilithiumSeedExpansion SubtleToProto(
      crypto::tink::subtle::DilithiumSeedExpansion expansion);

  static crypto::tink::subtle::DilithiumSeedExpansion ProtoToSubtle(
      google::crypto::tink::DilithiumSeedExpansion expansion);

  // SphincsHashType.
  static google::crypto::tink::SphincsHashType SubtleToProto(
      crypto::tink::subtle::SphincsHashType type);

  static crypto::tink::subtle::SphincsHashType ProtoToSubtle(
      google::crypto::tink::SphincsHashType type);

  // SphincsVariant.
  static google::crypto::tink::SphincsVariant SubtleToProto(
      crypto::tink::subtle::SphincsVariant variant);

  static crypto::tink::subtle::SphincsVariant ProtoToSubtle(
      google::crypto::tink::SphincsVariant variant);

  // SphincsSignatureType.
  static google::crypto::tink::SphincsSignatureType SubtleToProto(
      crypto::tink::subtle::SphincsSignatureType type);

  static crypto::tink::subtle::SphincsSignatureType ProtoToSubtle(
      google::crypto::tink::SphincsSignatureType type);
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_UTIL_ENUMS_H_
