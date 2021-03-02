// Copyright 2017 Google Inc.
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

#include "tink/subtle/common_enums.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

class CommonEnumsTest : public ::testing::Test {};

TEST_F(CommonEnumsTest, testEllipticCurveTypeToString) {
  EXPECT_EQ("NIST_P256", EnumToString(EllipticCurveType::NIST_P256));
  EXPECT_EQ("NIST_P384", EnumToString(EllipticCurveType::NIST_P384));
  EXPECT_EQ("NIST_P521", EnumToString(EllipticCurveType::NIST_P521));
  EXPECT_EQ("UNKNOWN_CURVE", EnumToString(EllipticCurveType::UNKNOWN_CURVE));
  EXPECT_EQ("UNKNOWN_CURVE: 42", EnumToString((EllipticCurveType)42));
}

TEST_F(CommonEnumsTest, testHashTypeToString) {
  EXPECT_EQ("SHA1", EnumToString(HashType::SHA1));
  EXPECT_EQ("SHA224", EnumToString(HashType::SHA224));
  EXPECT_EQ("SHA256", EnumToString(HashType::SHA256));
  EXPECT_EQ("SHA384", EnumToString(HashType::SHA384));
  EXPECT_EQ("SHA512", EnumToString(HashType::SHA512));
  EXPECT_EQ("UNKNOWN_HASH", EnumToString(HashType::UNKNOWN_HASH));
  EXPECT_EQ("UNKNOWN_HASH: 42", EnumToString((HashType)42));
}

TEST_F(CommonEnumsTest, testEcPointFormatToString) {
  EXPECT_EQ("UNCOMPRESSED", EnumToString(EcPointFormat::UNCOMPRESSED));
  EXPECT_EQ("COMPRESSED", EnumToString(EcPointFormat::COMPRESSED));
  EXPECT_EQ("DO_NOT_USE_CRUNCHY_UNCOMPRESSED",
            EnumToString(EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED));

  EXPECT_EQ("UNKNOWN_FORMAT", EnumToString(EcPointFormat::UNKNOWN_FORMAT));
  EXPECT_EQ("UNKNOWN_FORMAT: 42", EnumToString((EcPointFormat)42));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
