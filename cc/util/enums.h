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

#include "tink/subtle/common_enums.h"
#include "proto/common.pb.h"

namespace crypto {
namespace tink {
namespace util {


// Helpers for translation between protocol buffer enums and
// common enums used in subtle.
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
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_ENUMS_H_
