// Copyright 2022 Google LLC
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

#include "tink/mac/aes_cmac_key.h"

#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/types/optional.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::Combine;
using ::testing::Eq;
using ::testing::Range;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  AesCmacParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using AesCmacKeyTest = TestWithParam<std::tuple<int, int, TestCase>>;

INSTANTIATE_TEST_SUITE_P(
    AesCmacKeyTestSuite, AesCmacKeyTest,
    Combine(Values(16, 32), Range(10, 16),
            Values(TestCase{AesCmacParameters::Variant::kTink, 0x02030400,
                            std::string("\x01\x02\x03\x04\x00", 5)},
                   TestCase{AesCmacParameters::Variant::kCrunchy, 0x01030005,
                            std::string("\x00\x01\x03\x00\x05", 5)},
                   TestCase{AesCmacParameters::Variant::kLegacy, 0x01020304,
                            std::string("\x00\x01\x02\x03\x04", 5)},
                   TestCase{AesCmacParameters::Variant::kNoPrefix,
                            absl::nullopt, ""})));

TEST_P(AesCmacKeyTest, CreateSucceeds) {
  int key_size;
  int cryptographic_tag_size;
  TestCase test_case;
  std::tie(key_size, cryptographic_tag_size, test_case) = GetParam();

  util::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      key_size, cryptographic_tag_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  util::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*params, secret, test_case.id_requirement);
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), IsOkAndHolds(test_case.output_prefix));
}

TEST(AesCmacKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  // Key size parameter is 32 bytes.
  util::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  // Key material is 16 bytes (another valid key length).
  RestrictedData mismatched_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(
      AesCmacKey::Create(*params, mismatched_secret, /*id_requirement=*/123)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCmacKeyTest, CreateKeyWithWrongIdRequirementFails) {
  util::StatusOr<AesCmacParameters> no_prefix_params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());

  util::StatusOr<AesCmacParameters> tink_params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(
      AesCmacKey::Create(*no_prefix_params, secret, /*id_requirement=*/123)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacKey::Create(*tink_params, secret,
                                 /*id_requirement=*/absl::nullopt)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesCmacKeyTest, GetAesCmacKey) {
  int key_size;
  int cryptographic_tag_size;
  TestCase test_case;
  std::tie(key_size, cryptographic_tag_size, test_case) = GetParam();

  util::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      key_size, cryptographic_tag_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);

  util::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*params, secret, test_case.id_requirement);
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetAesKey(), IsOkAndHolds(secret));
}

TEST_P(AesCmacKeyTest, KeyEquals) {
  int key_size;
  int cryptographic_tag_size;
  TestCase test_case;
  std::tie(key_size, cryptographic_tag_size, test_case) = GetParam();

  util::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      key_size, cryptographic_tag_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  util::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*params, secret, test_case.id_requirement);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesCmacKey> other_key =
      AesCmacKey::Create(*params, secret, test_case.id_requirement);
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesCmacKeyTest, DifferentFormatNotEqual) {
  util::StatusOr<AesCmacParameters> legacy_params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kLegacy);
  ASSERT_THAT(legacy_params, IsOk());

  util::StatusOr<AesCmacParameters> tink_params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*legacy_params, secret, /*id_requirement=*/0x01020304);
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<AesCmacKey> other_key =
      AesCmacKey::Create(*tink_params, secret, /*id_requirement=*/0x01020304);
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCmacKeyTest, DifferentSecretDataNotEqual) {
  util::StatusOr<AesCmacParameters> params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*params, secret1, /*id_requirement=*/0x01020304);
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<AesCmacKey> other_key =
      AesCmacKey::Create(*params, secret2, /*id_requirement=*/0x01020304);
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCmacKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<AesCmacParameters> params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*params, secret, /*id_requirement=*/0x01020304);
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<AesCmacKey> other_key =
      AesCmacKey::Create(*params, secret, /*id_requirement=*/0x02030405);
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
