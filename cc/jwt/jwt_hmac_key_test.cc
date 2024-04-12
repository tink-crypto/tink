// Copyright 2024 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_hmac_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  int key_size_in_bytes;
  JwtHmacParameters::KidStrategy kid_strategy;
  JwtHmacParameters::Algorithm algorithm;
  absl::optional<std::string> custom_kid;
  absl::optional<int> id_requirement;
  absl::optional<std::string> expected_kid;
};

using JwtHmacKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtHmacKeyTestSuite, JwtHmacKeyTest,
    Values(TestCase{/*key_size_in_bytes=*/16,
                    JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
                    JwtHmacParameters::Algorithm::kHs256,
                    /*custom_kid=*/absl::nullopt, /*id_requirement=*/123,
                    /*expected_kid=*/"AAAAew"},
           TestCase{/*key_size_in_bytes=*/32,
                    JwtHmacParameters::KidStrategy::kCustom,
                    JwtHmacParameters::Algorithm::kHs384,
                    /*custom_kid=*/"custom_kid",
                    /*id_requirement=*/absl::nullopt,
                    /*expected_kid=*/"custom_kid"},
           TestCase{/*key_size_in_bytes=*/32,
                    JwtHmacParameters::KidStrategy::kIgnored,
                    JwtHmacParameters::Algorithm::kHs512,
                    /*custom_kid=*/absl::nullopt,
                    /*id_requirement=*/absl::nullopt,
                    /*expected_kid=*/absl::nullopt}));

TEST_P(JwtHmacKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      test_case.key_size_in_bytes, test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(test_case.key_size_in_bytes);
  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder().SetParameters(*params).SetKeyBytes(secret);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  util::StatusOr<JwtHmacKey> key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetKid(), Eq(test_case.expected_kid));
}

TEST(JwtHmacKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  // Key size parameter is 32 bytes.
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  // Key material is 16 bytes (another valid key length).
  RestrictedData mismatched_secret = RestrictedData(/*num_random_bytes=*/16);
  JwtHmacKey::Builder builder = JwtHmacKey::Builder()
                                    .SetParameters(*params)
                                    .SetKeyBytes(mismatched_secret)
                                    .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Actual JWT HMAC key size does not match")));
}

TEST(JwtHmacKeyTest, CreateKeyWithoutKeyBytesFails) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder().SetParameters(*params).SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("JWT HMAC key bytes must be specified")));
}

TEST(JwtHmacKeyTest, CreateKeyWithoutParametersFails) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder().SetKeyBytes(secret).SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("JWT HMAC parameters must be specified")));
}

TEST(JwtHmacKeyTest, CreateBase64EncodedKidWithoutIdRequirementFails) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder().SetParameters(*params).SetKeyBytes(secret);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement "
                                 "with parameters with ID requirement")));
}

TEST(JwtHmacKeyTest, CreateBase64EncodedKidWithCustomKidFails) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  JwtHmacKey::Builder builder = JwtHmacKey::Builder()
                                    .SetParameters(*params)
                                    .SetKeyBytes(secret)
                                    .SetIdRequirement(123)
                                    .SetCustomKid("custom_kid");

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must not be set for "
                                 "KidStrategy::kBase64EncodedKeyId")));
}

TEST(JwtHmacKeyTest, CreateCustomKidWithIdRequirementFails) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kCustom,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  JwtHmacKey::Builder builder = JwtHmacKey::Builder()
                                    .SetParameters(*params)
                                    .SetKeyBytes(secret)
                                    .SetCustomKid("custom_kid")
                                    .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtHmacKeyTest, CreateCustomKidWithoutCustomKidFails) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kCustom,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder().SetParameters(*params).SetKeyBytes(secret);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must be set")));
}

TEST(JwtHmacKeyTest, CreateIgnoredKidWithIdRequirementFails) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kIgnored,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  JwtHmacKey::Builder builder = JwtHmacKey::Builder()
                                    .SetParameters(*params)
                                    .SetKeyBytes(secret)
                                    .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtHmacKeyTest, CreateIgnoredKidWithCustomKidFails) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kIgnored,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  JwtHmacKey::Builder builder = JwtHmacKey::Builder()
                                    .SetParameters(*params)
                                    .SetKeyBytes(secret)
                                    .SetCustomKid("custom_kid");

  EXPECT_THAT(
      builder.Build(GetPartialKeyAccess()).status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Custom kid must not be set for KidStrategy::kIgnored")));
}

TEST_P(JwtHmacKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      test_case.key_size_in_bytes, test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(test_case.key_size_in_bytes);
  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder().SetParameters(*params).SetKeyBytes(secret);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  util::StatusOr<JwtHmacKey> key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  JwtHmacKey::Builder other_builder =
      JwtHmacKey::Builder().SetParameters(*params).SetKeyBytes(secret);
  if (test_case.id_requirement.has_value()) {
    other_builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    other_builder.SetCustomKid(*test_case.custom_kid);
  }
  util::StatusOr<JwtHmacKey> other_key =
      other_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(JwtHmacKeyTest, DifferentParametersNotEqual) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<JwtHmacParameters> other_params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs384);
  ASSERT_THAT(other_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<JwtHmacKey> key = JwtHmacKey::Builder()
                                       .SetParameters(*params)
                                       .SetKeyBytes(secret)
                                       .SetIdRequirement(123)
                                       .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtHmacKey> other_key = JwtHmacKey::Builder()
                                             .SetParameters(*other_params)
                                             .SetKeyBytes(secret)
                                             .SetIdRequirement(123)
                                             .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtHmacKeyTest, DifferentSecretDataNotEqual) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData other_secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<JwtHmacKey> key = JwtHmacKey::Builder()
                                       .SetParameters(*params)
                                       .SetKeyBytes(secret)
                                       .SetIdRequirement(123)
                                       .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtHmacKey> other_key = JwtHmacKey::Builder()
                                             .SetParameters(*params)
                                             .SetKeyBytes(other_secret)
                                             .SetIdRequirement(123)
                                             .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtHmacKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<JwtHmacKey> key = JwtHmacKey::Builder()
                                       .SetParameters(*params)
                                       .SetKeyBytes(secret)
                                       .SetIdRequirement(123)
                                       .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtHmacKey> other_key = JwtHmacKey::Builder()
                                             .SetParameters(*params)
                                             .SetKeyBytes(secret)
                                             .SetIdRequirement(456)
                                             .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtHmacKeyTest, DifferentCustomKidNotEqual) {
  util::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kCustom,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<JwtHmacKey> key = JwtHmacKey::Builder()
                                       .SetParameters(*params)
                                       .SetKeyBytes(secret)
                                       .SetCustomKid("custom_kid")
                                       .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtHmacKey> other_key = JwtHmacKey::Builder()
                                             .SetParameters(*params)
                                             .SetKeyBytes(secret)
                                             .SetCustomKid("other_custom_kid")
                                             .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
