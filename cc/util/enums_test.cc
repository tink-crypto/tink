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

#include "tink/util/enums.h"

#include "tink/subtle/common_enums.h"
#include "gtest/gtest.h"
#include "proto/common.pb.h"

using crypto::tink::util::Enums;

namespace pb = google::crypto::tink;

namespace crypto {
namespace tink {
namespace {

class EnumsTest : public ::testing::Test {
};

TEST_F(EnumsTest, testEllipticCurveType) {
  EXPECT_EQ(pb::EllipticCurveType::NIST_P256,
            Enums::SubtleToProto(subtle::EllipticCurveType::NIST_P256));
  EXPECT_EQ(pb::EllipticCurveType::NIST_P384,
            Enums::SubtleToProto(subtle::EllipticCurveType::NIST_P384));
  EXPECT_EQ(pb::EllipticCurveType::NIST_P521,
            Enums::SubtleToProto(subtle::EllipticCurveType::NIST_P521));
  EXPECT_EQ(pb::EllipticCurveType::UNKNOWN_CURVE,
            Enums::SubtleToProto(subtle::EllipticCurveType::UNKNOWN_CURVE));
  EXPECT_EQ(pb::EllipticCurveType::UNKNOWN_CURVE,
            Enums::SubtleToProto((subtle::EllipticCurveType)42));

  EXPECT_EQ(subtle::EllipticCurveType::NIST_P256,
            Enums::ProtoToSubtle(pb::EllipticCurveType::NIST_P256));
  EXPECT_EQ(subtle::EllipticCurveType::NIST_P384,
            Enums::ProtoToSubtle(pb::EllipticCurveType::NIST_P384));
  EXPECT_EQ(subtle::EllipticCurveType::NIST_P521,
            Enums::ProtoToSubtle(pb::EllipticCurveType::NIST_P521));
  EXPECT_EQ(subtle::EllipticCurveType::UNKNOWN_CURVE,
            Enums::ProtoToSubtle(pb::EllipticCurveType::UNKNOWN_CURVE));
  EXPECT_EQ(subtle::EllipticCurveType::UNKNOWN_CURVE,
            Enums::ProtoToSubtle((pb::EllipticCurveType)42));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = (int)pb::EllipticCurveType_MIN;
       int_type <= (int)pb::EllipticCurveType_MAX;
       int_type++) {
    if (pb::EllipticCurveType_IsValid(int_type)) {
      pb::EllipticCurveType type = (pb::EllipticCurveType)int_type;
      EXPECT_EQ(type,
                Enums::SubtleToProto(Enums::ProtoToSubtle(type)));
      count++;
    }
  }
  EXPECT_EQ(4, count);
}

TEST_F(EnumsTest, testHashType) {
  EXPECT_EQ(pb::HashType::SHA1,
            Enums::SubtleToProto(subtle::HashType::SHA1));
  EXPECT_EQ(pb::HashType::SHA256,
            Enums::SubtleToProto(subtle::HashType::SHA256));
  EXPECT_EQ(pb::HashType::SHA512,
            Enums::SubtleToProto(subtle::HashType::SHA512));
  EXPECT_EQ(pb::HashType::UNKNOWN_HASH,
            Enums::SubtleToProto(subtle::HashType::UNKNOWN_HASH));
  EXPECT_EQ(pb::HashType::UNKNOWN_HASH,
            Enums::SubtleToProto((subtle::HashType)42));

  EXPECT_EQ(subtle::HashType::SHA1,
            Enums::ProtoToSubtle(pb::HashType::SHA1));
  EXPECT_EQ(subtle::HashType::SHA256,
            Enums::ProtoToSubtle(pb::HashType::SHA256));
  EXPECT_EQ(subtle::HashType::SHA512,
            Enums::ProtoToSubtle(pb::HashType::SHA512));
  EXPECT_EQ(subtle::HashType::UNKNOWN_HASH,
            Enums::ProtoToSubtle(pb::HashType::UNKNOWN_HASH));
  EXPECT_EQ(subtle::HashType::UNKNOWN_HASH,
            Enums::ProtoToSubtle((pb::HashType)42));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = (int)pb::HashType_MIN;
       int_type <= (int)pb::HashType_MAX;
       int_type++) {
    if (pb::HashType_IsValid(int_type)) {
      pb::HashType type = (pb::HashType)int_type;
      EXPECT_EQ(type,
                Enums::SubtleToProto(Enums::ProtoToSubtle(type)));
      count++;
    }
  }
  EXPECT_EQ(4, count);
}

TEST_F(EnumsTest, testEcPointFormat) {
  EXPECT_EQ(pb::EcPointFormat::UNCOMPRESSED,
            Enums::SubtleToProto(subtle::EcPointFormat::UNCOMPRESSED));
  EXPECT_EQ(pb::EcPointFormat::COMPRESSED,
            Enums::SubtleToProto(subtle::EcPointFormat::COMPRESSED));
  EXPECT_EQ(pb::EcPointFormat::UNKNOWN_FORMAT,
            Enums::SubtleToProto(subtle::EcPointFormat::UNKNOWN_FORMAT));
  EXPECT_EQ(pb::EcPointFormat::UNKNOWN_FORMAT,
            Enums::SubtleToProto((subtle::EcPointFormat)42));

  EXPECT_EQ(subtle::EcPointFormat::UNCOMPRESSED,
            Enums::ProtoToSubtle(pb::EcPointFormat::UNCOMPRESSED));
  EXPECT_EQ(subtle::EcPointFormat::COMPRESSED,
            Enums::ProtoToSubtle(pb::EcPointFormat::COMPRESSED));
  EXPECT_EQ(subtle::EcPointFormat::UNKNOWN_FORMAT,
            Enums::ProtoToSubtle(pb::EcPointFormat::UNKNOWN_FORMAT));
  EXPECT_EQ(subtle::EcPointFormat::UNKNOWN_FORMAT,
            Enums::ProtoToSubtle((pb::EcPointFormat)42));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_format = (int)pb::EcPointFormat_MIN;
       int_format <= (int)pb::EcPointFormat_MAX;
       int_format++) {
    if (pb::EcPointFormat_IsValid(int_format)) {
      pb::EcPointFormat format = (pb::EcPointFormat)int_format;
      EXPECT_EQ(format,
                Enums::SubtleToProto(Enums::ProtoToSubtle(format)));
      count++;
    }
  }
  EXPECT_EQ(3, count);
}

}  // namespace
}  // namespace tink
}  // namespace crypto

int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
