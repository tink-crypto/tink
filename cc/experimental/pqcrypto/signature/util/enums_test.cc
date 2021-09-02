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

}  // namespace
}  // namespace tink
}  // namespace crypto
