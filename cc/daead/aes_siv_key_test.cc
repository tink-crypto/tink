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

#include "tink/daead/aes_siv_key.h"

#include <string>
#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/daead/aes_siv_parameters.h"
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
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  AesSivParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using AesSivKeyTest = TestWithParam<std::tuple<int, TestCase>>;

INSTANTIATE_TEST_SUITE_P(
    AesSivKeyTestSuite, AesSivKeyTest,
    Combine(Values(32, 48, 64),
            Values(TestCase{AesSivParameters::Variant::kTink, 0x02030400,
                            std::string("\x01\x02\x03\x04\x00", 5)},
                   TestCase{AesSivParameters::Variant::kCrunchy, 0x01030005,
                            std::string("\x00\x01\x03\x00\x05", 5)},
                   TestCase{AesSivParameters::Variant::kNoPrefix, absl::nullopt,
                            ""})));

TEST_P(AesSivKeyTest, CreateSucceeds) {
  int key_size;
  TestCase test_case;
  std::tie(key_size, test_case) = GetParam();

  util::StatusOr<AesSivParameters> params =
      AesSivParameters::Create(key_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  util::StatusOr<AesSivKey> key = AesSivKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
}

TEST(AesSivKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  // Key size parameter is 64 bytes.
  util::StatusOr<AesSivParameters> params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  // Key material is 32 bytes (another valid key length).
  RestrictedData mismatched_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesSivKey::Create(*params, mismatched_secret,
                                /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesSivKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  util::StatusOr<AesSivParameters> no_prefix_params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());

  util::StatusOr<AesSivParameters> tink_params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/64);

  EXPECT_THAT(AesSivKey::Create(*no_prefix_params, secret,
                                /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      AesSivKey::Create(*tink_params, secret,
                        /*id_requirement=*/absl::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesSivKeyTest, GetKeyBytes) {
  int key_size;
  TestCase test_case;
  std::tie(key_size, test_case) = GetParam();

  util::StatusOr<AesSivParameters> params =
      AesSivParameters::Create(key_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);

  util::StatusOr<AesSivKey> key = AesSivKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
}

TEST_P(AesSivKeyTest, KeyEquals) {
  int key_size;
  TestCase test_case;
  std::tie(key_size, test_case) = GetParam();

  util::StatusOr<AesSivParameters> params =
      AesSivParameters::Create(key_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  util::StatusOr<AesSivKey> key = AesSivKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesSivKey> other_key = AesSivKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesSivKeyTest, DifferentVariantNotEqual) {
  util::StatusOr<AesSivParameters> crunchy_params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kCrunchy);
  ASSERT_THAT(crunchy_params, IsOk());

  util::StatusOr<AesSivParameters> tink_params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/64);

  util::StatusOr<AesSivKey> key =
      AesSivKey::Create(*crunchy_params, secret, /*id_requirement=*/0x01020304,
                        GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesSivKey> other_key =
      AesSivKey::Create(*tink_params, secret, /*id_requirement=*/0x01020304,
                        GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesSivKeyTest, DifferentSecretDataNotEqual) {
  util::StatusOr<AesSivParameters> params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/64);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/64);

  util::StatusOr<AesSivKey> key = AesSivKey::Create(
      *params, secret1, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesSivKey> other_key = AesSivKey::Create(
      *params, secret2, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesSivKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<AesSivParameters> params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/64);

  util::StatusOr<AesSivKey> key = AesSivKey::Create(
      *params, secret, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesSivKey> other_key = AesSivKey::Create(
      *params, secret, /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
