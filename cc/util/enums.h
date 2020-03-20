// Copyright 2017 Google Inc.
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

#ifndef TINK_UTIL_ENUMS_H_
#define TINK_UTIL_ENUMS_H_

#include "absl/strings/string_view.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace util {

// Helpers for translation of common enums between protocol buffer enums,
// their string representation, and common enums used in subtle.
class Enums {
 public:
  // EllipticCurveType.
  static google::crypto::tink::EllipticCurveType SubtleToProto(
      crypto::tink::subtle::EllipticCurveType type);

  static crypto::tink::subtle::EllipticCurveType ProtoToSubtle(
      google::crypto::tink::EllipticCurveType type);

  // EcPointFormat.
  static google::crypto::tink::EcPointFormat SubtleToProto(
      crypto::tink::subtle::EcPointFormat format);

  static crypto::tink::subtle::EcPointFormat ProtoToSubtle(
      google::crypto::tink::EcPointFormat format);

  // HashType.
  static google::crypto::tink::HashType SubtleToProto(
      crypto::tink::subtle::HashType type);

  static crypto::tink::subtle::HashType ProtoToSubtle(
      google::crypto::tink::HashType type);

  // Returns the length in bytes of the given hash type `hash_type`. Returns
  // INVALID_ARGUMENT if the algorithm is unsupported.
  static util::StatusOr<int> HashLength(
      google::crypto::tink::HashType hash_type);

  // EcdsaSignatureEncoding.
  static google::crypto::tink::EcdsaSignatureEncoding SubtleToProto(
      crypto::tink::subtle::EcdsaSignatureEncoding encoding);

  static crypto::tink::subtle::EcdsaSignatureEncoding ProtoToSubtle(
      google::crypto::tink::EcdsaSignatureEncoding encoding);

  // Printable names for common enums.
  static const char* KeyStatusName(
      google::crypto::tink::KeyStatusType key_status_type);
  static const char* HashName(google::crypto::tink::HashType hash_type);
  static const char* KeyMaterialName(
      google::crypto::tink::KeyData::KeyMaterialType key_material_type);
  static const char* OutputPrefixName(
      google::crypto::tink::OutputPrefixType output_prefix_type);

  static google::crypto::tink::KeyStatusType KeyStatus(absl::string_view name);
  static google::crypto::tink::HashType Hash(absl::string_view name);
  static google::crypto::tink::KeyData::KeyMaterialType KeyMaterial(
      absl::string_view name);
  static google::crypto::tink::OutputPrefixType OutputPrefix(
      absl::string_view name);
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_ENUMS_H_
