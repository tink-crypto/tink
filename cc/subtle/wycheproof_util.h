// Copyright 2018 Google Inc.
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

#ifndef TINK_SUBTLE_WYCHEPROOF_UTIL_H_
#define TINK_SUBTLE_WYCHEPROOF_UTIL_H_

#include <memory>
#include <string>

#include "include/rapidjson/document.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace subtle {

// WycheproofUtil is a util that is used to read test vectors from project
// Wycheproof and convert the values in the test vectors into corresponding
// values for tink.
class WycheproofUtil {
 public:
  // Converts a JSON value into a byte array.
  // Byte arrays are always hexadecimal representation.
  static std::string GetBytes(const rapidjson::Value &val);

  // Reads test vector from a file.
  // The filename is relative to the directory with the test vectors.
  static std::unique_ptr<rapidjson::Document> ReadTestVectors(
      const std::string &filename);

  static HashType GetHashType(const rapidjson::Value &val);

  static EllipticCurveType GetEllipticCurveType(const rapidjson::Value &val);

  // Integers in Wycheproof are represented as signed bigendian hexadecimal
  // strings in twos complement representation.
  // Integers in EcKey are unsigned and are represented as an array of bytes
  // using bigendian order.
  // GetInteger can assume that val is always 0 or a positive integer, since
  // they are values from the key: a convention in Wycheproof is that parameters
  // in the test group are valid, only values in the test vector itself may
  // be invalid.
  static std::string GetInteger(const rapidjson::Value &val);
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_WYCHEPROOF_UTIL_H_
