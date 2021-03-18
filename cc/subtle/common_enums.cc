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

#include "tink/subtle/common_enums.h"

#include <string>

#include "absl/strings/str_cat.h"

namespace crypto {
namespace tink {
namespace subtle {

std::string EnumToString(EllipticCurveType type) {
  switch (type) {
  case EllipticCurveType::NIST_P256:
    return "NIST_P256";
  case EllipticCurveType::NIST_P384:
    return "NIST_P384";
  case EllipticCurveType::NIST_P521:
    return "NIST_P521";
  case EllipticCurveType::CURVE25519:
    return "CURVE25519";
  case EllipticCurveType::UNKNOWN_CURVE:
    return "UNKNOWN_CURVE";
  default:
    return absl::StrCat("UNKNOWN_CURVE: ", type);
  }
}

std::string EnumToString(EcPointFormat format) {
  switch (format) {
  case EcPointFormat::UNCOMPRESSED:
    return "UNCOMPRESSED";
  case EcPointFormat::COMPRESSED:
    return "COMPRESSED";
  case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
    return "DO_NOT_USE_CRUNCHY_UNCOMPRESSED";
  case EcPointFormat::UNKNOWN_FORMAT:
    return "UNKNOWN_FORMAT";
  default:
    return absl::StrCat("UNKNOWN_FORMAT: ", format);
  }
}

std::string EnumToString(HashType type) {
  switch (type) {
  case HashType::SHA1:
    return "SHA1";
  case HashType::SHA224:
    return "SHA224";
  case HashType::SHA256:
    return "SHA256";
  case HashType::SHA384:
    return "SHA384";
  case HashType::SHA512:
    return "SHA512";
  case HashType::UNKNOWN_HASH:
    return "UNKNOWN_HASH";
  default:
    return absl::StrCat("UNKNOWN_HASH: ", type);
  }
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
