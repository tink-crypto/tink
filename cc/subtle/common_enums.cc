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
  case EllipticCurveType::UNKNOWN_CURVE:
    return "UNKNOWN_CURVE";
  default:
    return "UNKNOWN_CURVE: " + std::to_string(type);
  }
}

std::string EnumToString(EcPointFormat format) {
  switch (format) {
  case EcPointFormat::UNCOMPRESSED:
    return "UNCOMPRESSED";
  case EcPointFormat::COMPRESSED:
    return "COMPRESSED";
  case EcPointFormat::UNKNOWN_FORMAT:
    return "UNKNOWN_FORMAT";
  default:
    return "UNKNOWN_FORMAT: " + std::to_string(format);
  }
}

std::string EnumToString(HashType type) {
  switch (type) {
  case HashType::SHA1:
    return "SHA1";
  case HashType::SHA256:
    return "SHA256";
  case HashType::SHA512:
    return "SHA512";
  case HashType::UNKNOWN_HASH:
    return "UNKNOWN_HASH";
  default:
    return "UNKNOWN_HASH: " + std::to_string(type);
  }
}

std::string EnumToString(RsaSignatureEncoding encoding) {
  switch (encoding) {
    case RsaSignatureEncoding::PKCS1_ENCODING:
      return "PKCS1_ENCODING";
    case RsaSignatureEncoding::PSS_ENCODING:
      return "PSS_ENCODING";
    case RsaSignatureEncoding::UNKNOWN_ENCODING:
      return "UNKNOWN_ENCODING";
    default:
      return "UNKNOWN_ENCODING" + std::to_string(encoding);
  }
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
