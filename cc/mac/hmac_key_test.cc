// Copyright 2023 Google LLC
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

#include "tink/mac/hmac_key.h"

#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Combine;
using ::testing::Eq;
using ::testing::Range;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  HmacParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using HmacKeyTest =
    TestWithParam<std::tuple<int, int, HmacParameters::HashType, TestCase>>;

INSTANTIATE_TEST_SUITE_P(
    HmacKeyTestSuite, HmacKeyTest,
    Combine(Values(16, 32), Range(10, 20),
            Values(HmacParameters::HashType::kSha1,
                   HmacParameters::HashType::kSha224,
                   HmacParameters::HashType::kSha256,
                   HmacParameters::HashType::kSha384,
                   HmacParameters::HashType::kSha512),
            Values(TestCase{HmacParameters::Variant::kTink, 0x02030400,
                            std::string("\x01\x02\x03\x04\x00", 5)},
                   TestCase{HmacParameters::Variant::kCrunchy, 0x01030005,
                            std::string("\x00\x01\x03\x00\x05", 5)},
                   TestCase{HmacParameters::Variant::kLegacy, 0x01020304,
                            std::string("\x00\x01\x02\x03\x04", 5)},
                   TestCase{HmacParameters::Variant::kNoPrefix, absl::nullopt,
                            ""})));

TEST_P(HmacKeyTest, CreateSucceeds) {
  int key_size;
  int cryptographic_tag_size;
  HmacParameters::HashType hash_type;
  TestCase test_case;
  std::tie(key_size, cryptographic_tag_size, hash_type, test_case) = GetParam();

  util::StatusOr<HmacParameters> params = HmacParameters::Create(
      key_size, cryptographic_tag_size, hash_type, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  util::StatusOr<HmacKey> key = HmacKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
}

TEST(HmacKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  // Key size parameter is 32 bytes.
  util::StatusOr<HmacParameters> params = HmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha256, HmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  // Key material is 16 bytes (another valid key length).
  RestrictedData mismatched_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(HmacKey::Create(*params, mismatched_secret,
                              /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HmacKeyTest, CreateKeyWithWrongIdRequirementFails) {
  util::StatusOr<HmacParameters> no_prefix_params = HmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha512, HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());

  util::StatusOr<HmacParameters> tink_params = HmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha512, HmacParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(HmacKey::Create(*no_prefix_params, secret,
                              /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      HmacKey::Create(*tink_params, secret,
                      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HmacKeyTest, GetKeyBytes) {
  int key_size;
  int cryptographic_tag_size;
  HmacParameters::HashType hash_type;
  TestCase test_case;
  std::tie(key_size, cryptographic_tag_size, hash_type, test_case) = GetParam();

  util::StatusOr<HmacParameters> params = HmacParameters::Create(
      key_size, cryptographic_tag_size, hash_type, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);

  util::StatusOr<HmacKey> key = HmacKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
}

TEST_P(HmacKeyTest, KeyEquals) {
  int key_size;
  int cryptographic_tag_size;
  HmacParameters::HashType hash_type;
  TestCase test_case;
  std::tie(key_size, cryptographic_tag_size, hash_type, test_case) = GetParam();

  util::StatusOr<HmacParameters> params = HmacParameters::Create(
      key_size, cryptographic_tag_size, hash_type, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  util::StatusOr<HmacKey> key = HmacKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<HmacKey> other_key = HmacKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(HmacKeyTest, DifferentFormatNotEqual) {
  util::StatusOr<HmacParameters> legacy_params = HmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha256, HmacParameters::Variant::kLegacy);
  ASSERT_THAT(legacy_params, IsOk());

  util::StatusOr<HmacParameters> tink_params = HmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha256, HmacParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<HmacKey> key =
      HmacKey::Create(*legacy_params, secret, /*id_requirement=*/0x01020304,
                      GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<HmacKey> other_key =
      HmacKey::Create(*tink_params, secret, /*id_requirement=*/0x01020304,
                      GetPartialKeyAccess());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(HmacKeyTest, DifferentSecretDataNotEqual) {
  util::StatusOr<HmacParameters> params = HmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha384, HmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<HmacKey> key = HmacKey::Create(
      *params, secret1, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<HmacKey> other_key = HmacKey::Create(
      *params, secret2, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(HmacKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<HmacParameters> params = HmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha224, HmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<HmacKey> key = HmacKey::Create(
      *params, secret, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<HmacKey> other_key = HmacKey::Create(
      *params, secret, /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
