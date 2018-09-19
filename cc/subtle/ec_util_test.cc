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
#include "tink/subtle/ec_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

TEST(EcUtilTest, testFieldSizeInBytes) {
  EXPECT_EQ(256/8, EcUtil::FieldSizeInBytes(EllipticCurveType::NIST_P256));
  EXPECT_EQ(384/8, EcUtil::FieldSizeInBytes(EllipticCurveType::NIST_P384));
  EXPECT_EQ((521 + 7)/8,
            EcUtil::FieldSizeInBytes(EllipticCurveType::NIST_P521));

  EXPECT_EQ(0, EcUtil::FieldSizeInBytes(EllipticCurveType::UNKNOWN_CURVE));
}

TEST(EcUtilTest, testEncodingSizeInBytes) {
  EXPECT_EQ(2 * (256/8) + 1,
            EcUtil::EncodingSizeInBytes(EllipticCurveType::NIST_P256,
                                        EcPointFormat::UNCOMPRESSED)
            .ValueOrDie());
  EXPECT_EQ(256/8 + 1,
            EcUtil::EncodingSizeInBytes(EllipticCurveType::NIST_P256,
                                        EcPointFormat::COMPRESSED)
            .ValueOrDie());
  EXPECT_EQ(2 * (384/8) + 1,
            EcUtil::EncodingSizeInBytes(EllipticCurveType::NIST_P384,
                                        EcPointFormat::UNCOMPRESSED)
            .ValueOrDie());
  EXPECT_EQ(384/8 + 1,
            EcUtil::EncodingSizeInBytes(EllipticCurveType::NIST_P384,
                                        EcPointFormat::COMPRESSED)
            .ValueOrDie());
  EXPECT_EQ(2 * ((521 + 7)/8) + 1,
            EcUtil::EncodingSizeInBytes(EllipticCurveType::NIST_P521,
                                        EcPointFormat::UNCOMPRESSED)
            .ValueOrDie());
  EXPECT_EQ((521 + 7)/8 + 1,
            EcUtil::EncodingSizeInBytes(EllipticCurveType::NIST_P521,
                                        EcPointFormat::COMPRESSED)
            .ValueOrDie());

  EXPECT_FALSE(EcUtil::EncodingSizeInBytes(EllipticCurveType::NIST_P256,
                                           EcPointFormat::UNKNOWN_FORMAT).ok());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
