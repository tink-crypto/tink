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

#ifndef TINK_SUBTLE_COMMON_ENUMS_H_
#define TINK_SUBTLE_COMMON_ENUMS_H_

#include <string>

namespace crypto {
namespace tink {
namespace subtle {

// Common enums used by classes in subtle.
enum EllipticCurveType {
  UNKNOWN_CURVE = 0,
  NIST_P256 = 2,
  NIST_P384 = 3,
  NIST_P521 = 4,
  CURVE25519 = 5,
};

enum EcPointFormat {
  UNKNOWN_FORMAT = 0,
  UNCOMPRESSED = 1,
  COMPRESSED = 2,
  // Like UNCOMPRESSED but without the \x04 prefix. Crunchy uses this format.
  // DO NOT USE unless you are a Crunchy user moving to Tink.
  DO_NOT_USE_CRUNCHY_UNCOMPRESSED = 3,
};

enum HashType {
  UNKNOWN_HASH = 0,
  SHA1 = 1,  // SHA1 for digital signature is deprecated but HMAC-SHA1 is fine.
  SHA384 = 2,
  SHA256 = 3,
  SHA512 = 4,
  SHA224 = 5,
};

enum EcdsaSignatureEncoding {
  UNKNOWN_ENCODING = 0,
  IEEE_P1363 = 1,
  DER = 2,
};

std::string EnumToString(EllipticCurveType type);
std::string EnumToString(EcPointFormat format);
std::string EnumToString(HashType type);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_COMMON_ENUMS_H_
