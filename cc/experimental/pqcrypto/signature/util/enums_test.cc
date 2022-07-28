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

#include "tink/experimental/pqcrypto/signature/util/enums.h"

#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace {

namespace pb = google::crypto::tink;
using crypto::tink::util::EnumsPqcrypto;

class EnumsTest : public ::testing::Test {};

TEST_F(EnumsTest, DilithiumSeedExpansion) {
  EXPECT_EQ(pb::DilithiumSeedExpansion::SEED_EXPANSION_SHAKE,
            EnumsPqcrypto::SubtleToProto(
                subtle::DilithiumSeedExpansion::SEED_EXPANSION_SHAKE));
  EXPECT_EQ(pb::DilithiumSeedExpansion::SEED_EXPANSION_AES,
            EnumsPqcrypto::SubtleToProto(
                subtle::DilithiumSeedExpansion::SEED_EXPANSION_AES));
  EXPECT_EQ(pb::DilithiumSeedExpansion::SEED_EXPANSION_UNKNOWN,
            EnumsPqcrypto::SubtleToProto(
                subtle::DilithiumSeedExpansion::SEED_EXPANSION_UNKNOWN));

  EXPECT_EQ(subtle::DilithiumSeedExpansion::SEED_EXPANSION_SHAKE,
            EnumsPqcrypto::ProtoToSubtle(
                pb::DilithiumSeedExpansion::SEED_EXPANSION_SHAKE));
  EXPECT_EQ(subtle::DilithiumSeedExpansion::SEED_EXPANSION_AES,
            EnumsPqcrypto::ProtoToSubtle(
                pb::DilithiumSeedExpansion::SEED_EXPANSION_AES));
  EXPECT_EQ(subtle::DilithiumSeedExpansion::SEED_EXPANSION_UNKNOWN,
            EnumsPqcrypto::ProtoToSubtle(
                pb::DilithiumSeedExpansion::SEED_EXPANSION_UNKNOWN));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = static_cast<int>(pb::DilithiumSeedExpansion_MIN);
       int_type <= static_cast<int>(pb::DilithiumSeedExpansion_MAX);
       int_type++) {
    if (pb::DilithiumSeedExpansion_IsValid(int_type)) {
      pb::DilithiumSeedExpansion type =
          static_cast<pb::DilithiumSeedExpansion>(int_type);
      EXPECT_EQ(type, EnumsPqcrypto::SubtleToProto(
                          EnumsPqcrypto::ProtoToSubtle(type)));
      count++;
    }
  }
  EXPECT_EQ(3, count);
}

TEST_F(EnumsTest, SphincsHashType) {
  EXPECT_EQ(pb::SphincsHashType::HARAKA,
            EnumsPqcrypto::SubtleToProto(subtle::SphincsHashType::HARAKA));
  EXPECT_EQ(pb::SphincsHashType::SHA256,
            EnumsPqcrypto::SubtleToProto(subtle::SphincsHashType::SHA256));
  EXPECT_EQ(pb::SphincsHashType::SHAKE256,
            EnumsPqcrypto::SubtleToProto(subtle::SphincsHashType::SHAKE256));
  EXPECT_EQ(pb::SphincsHashType::HASH_TYPE_UNSPECIFIED,
            EnumsPqcrypto::SubtleToProto(
                subtle::SphincsHashType::HASH_TYPE_UNSPECIFIED));

  EXPECT_EQ(subtle::SphincsHashType::HARAKA,
            EnumsPqcrypto::ProtoToSubtle(pb::SphincsHashType::HARAKA));
  EXPECT_EQ(subtle::SphincsHashType::SHA256,
            EnumsPqcrypto::ProtoToSubtle(pb::SphincsHashType::SHA256));
  EXPECT_EQ(subtle::SphincsHashType::SHAKE256,
            EnumsPqcrypto::ProtoToSubtle(pb::SphincsHashType::SHAKE256));
  EXPECT_EQ(
      subtle::SphincsHashType::HASH_TYPE_UNSPECIFIED,
      EnumsPqcrypto::ProtoToSubtle(pb::SphincsHashType::HASH_TYPE_UNSPECIFIED));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = static_cast<int>(pb::SphincsHashType_MIN);
       int_type <= static_cast<int>(pb::SphincsHashType_MAX); int_type++) {
    if (pb::SphincsHashType_IsValid(int_type)) {
      pb::SphincsHashType type = static_cast<pb::SphincsHashType>(int_type);
      EXPECT_EQ(type, EnumsPqcrypto::SubtleToProto(
                          EnumsPqcrypto::ProtoToSubtle(type)));
      count++;
    }
  }
  EXPECT_EQ(4, count);
}

TEST_F(EnumsTest, SphincsVariant) {
  EXPECT_EQ(pb::SphincsVariant::ROBUST,
            EnumsPqcrypto::SubtleToProto(subtle::SphincsVariant::ROBUST));
  EXPECT_EQ(pb::SphincsVariant::SIMPLE,
            EnumsPqcrypto::SubtleToProto(subtle::SphincsVariant::SIMPLE));
  EXPECT_EQ(pb::SphincsVariant::VARIANT_UNSPECIFIED,
            EnumsPqcrypto::SubtleToProto(
                subtle::SphincsVariant::VARIANT_UNSPECIFIED));

  EXPECT_EQ(subtle::SphincsVariant::ROBUST,
            EnumsPqcrypto::ProtoToSubtle(pb::SphincsVariant::ROBUST));
  EXPECT_EQ(subtle::SphincsVariant::SIMPLE,
            EnumsPqcrypto::ProtoToSubtle(pb::SphincsVariant::SIMPLE));
  EXPECT_EQ(
      subtle::SphincsVariant::VARIANT_UNSPECIFIED,
      EnumsPqcrypto::ProtoToSubtle(pb::SphincsVariant::VARIANT_UNSPECIFIED));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = static_cast<int>(pb::SphincsVariant_MIN);
       int_type <= static_cast<int>(pb::SphincsVariant_MAX); int_type++) {
    if (pb::SphincsVariant_IsValid(int_type)) {
      pb::SphincsVariant type = static_cast<pb::SphincsVariant>(int_type);
      EXPECT_EQ(type, EnumsPqcrypto::SubtleToProto(
                          EnumsPqcrypto::ProtoToSubtle(type)));
      count++;
    }
  }
  EXPECT_EQ(3, count);
}

TEST_F(EnumsTest, SphincsSignatureType) {
  EXPECT_EQ(
      pb::SphincsSignatureType::FAST_SIGNING,
      EnumsPqcrypto::SubtleToProto(subtle::SphincsSignatureType::FAST_SIGNING));
  EXPECT_EQ(pb::SphincsSignatureType::SMALL_SIGNATURE,
            EnumsPqcrypto::SubtleToProto(
                subtle::SphincsSignatureType::SMALL_SIGNATURE));
  EXPECT_EQ(pb::SphincsSignatureType::SIG_TYPE_UNSPECIFIED,
            EnumsPqcrypto::SubtleToProto(
                subtle::SphincsSignatureType::SIG_TYPE_UNSPECIFIED));

  EXPECT_EQ(
      subtle::SphincsSignatureType::FAST_SIGNING,
      EnumsPqcrypto::ProtoToSubtle(pb::SphincsSignatureType::FAST_SIGNING));
  EXPECT_EQ(
      subtle::SphincsSignatureType::SMALL_SIGNATURE,
      EnumsPqcrypto::ProtoToSubtle(pb::SphincsSignatureType::SMALL_SIGNATURE));
  EXPECT_EQ(subtle::SphincsSignatureType::SIG_TYPE_UNSPECIFIED,
            EnumsPqcrypto::ProtoToSubtle(
                pb::SphincsSignatureType::SIG_TYPE_UNSPECIFIED));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = static_cast<int>(pb::SphincsSignatureType_MIN);
       int_type <= static_cast<int>(pb::SphincsSignatureType_MAX); int_type++) {
    if (pb::SphincsSignatureType_IsValid(int_type)) {
      pb::SphincsSignatureType type =
          static_cast<pb::SphincsSignatureType>(int_type);
      EXPECT_EQ(type, EnumsPqcrypto::SubtleToProto(
                          EnumsPqcrypto::ProtoToSubtle(type)));
      count++;
    }
  }
  EXPECT_EQ(3, count);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
