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

#include "tink/jwt/jwt_hmac_parameters.h"

#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Combine;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct KidStrategyTuple {
  JwtHmacParameters::KidStrategy kid_strategy;
  bool allowed_kid_absent;
  bool has_id_requirement;
};

using JwtHmacParametersTest = TestWithParam<
    std::tuple<int, KidStrategyTuple, JwtHmacParameters::Algorithm>>;

INSTANTIATE_TEST_SUITE_P(
    JwtHmacParametersTestSuite, JwtHmacParametersTest,
    Combine(Values(16, 32),
            Values(
                KidStrategyTuple{
                    JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
                    /*allowed_kid_absent=*/false, /*has_id_requirement=*/true},
                KidStrategyTuple{JwtHmacParameters::KidStrategy::kCustom,
                                 /*allowed_kid_absent=*/true,
                                 /*has_id_requirement=*/false},
                KidStrategyTuple{JwtHmacParameters::KidStrategy::kIgnored,
                                 /*allowed_kid_absent=*/true,
                                 /*has_id_requirement=*/false}),
            Values(JwtHmacParameters::Algorithm::kHs256,
                   JwtHmacParameters::Algorithm::kHs384,
                   JwtHmacParameters::Algorithm::kHs512)));

TEST_P(JwtHmacParametersTest, Create) {
  int key_size_in_bytes;
  KidStrategyTuple tuple;
  JwtHmacParameters::Algorithm algorithm;
  std::tie(key_size_in_bytes, tuple, algorithm) = GetParam();

  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      key_size_in_bytes, tuple.kid_strategy, algorithm);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(key_size_in_bytes));
  EXPECT_THAT(parameters->GetKidStrategy(), Eq(tuple.kid_strategy));
  EXPECT_THAT(parameters->AllowKidAbsent(), Eq(tuple.allowed_kid_absent));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(tuple.has_id_requirement));
  EXPECT_THAT(parameters->GetAlgorithm(), Eq(algorithm));
}

TEST(JwtHmacParametersTest, CreateWithInvalidKidStrategyFails) {
  EXPECT_THAT(JwtHmacParameters::Create(
                  /*key_size_in_bytes=*/16,
                  JwtHmacParameters::KidStrategy::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  JwtHmacParameters::Algorithm::kHs512)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown kid strategy")));
}

TEST(JwtHmacParametersTest, CreateWithInvalidAlgorithmFails) {
  EXPECT_THAT(JwtHmacParameters::Create(
                  /*key_size_in_bytes=*/16,
                  JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
                  JwtHmacParameters::Algorithm::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown algorithm")));
}

TEST(JwtHmacParametersTest, CreateWithInvalidKeySizeFails) {
  EXPECT_THAT(JwtHmacParameters::Create(
                  /*key_size_in_bytes=*/15,
                  JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
                  JwtHmacParameters::Algorithm::kHs512)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key size should be at least 16 bytes")));
}

TEST(JwtHmacParametersTest, CopyConstructor) {
  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/16,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs512);
  ASSERT_THAT(parameters, IsOk());

  JwtHmacParameters copy(*parameters);

  EXPECT_THAT(copy.KeySizeInBytes(), Eq(parameters->KeySizeInBytes()));
  EXPECT_THAT(copy.GetKidStrategy(), Eq(parameters->GetKidStrategy()));
  EXPECT_THAT(copy.GetAlgorithm(), Eq(parameters->GetAlgorithm()));
  EXPECT_THAT(copy.AllowKidAbsent(), Eq(parameters->AllowKidAbsent()));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(parameters->HasIdRequirement()));
}

TEST(JwtHmacParametersTest, CopyAssignment) {
  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/16,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs512);
  ASSERT_THAT(parameters, IsOk());

  JwtHmacParameters copy = *parameters;

  EXPECT_THAT(copy.KeySizeInBytes(), Eq(parameters->KeySizeInBytes()));
  EXPECT_THAT(copy.GetKidStrategy(), Eq(parameters->GetKidStrategy()));
  EXPECT_THAT(copy.GetAlgorithm(), Eq(parameters->GetAlgorithm()));
  EXPECT_THAT(copy.AllowKidAbsent(), Eq(parameters->AllowKidAbsent()));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(parameters->HasIdRequirement()));
}

TEST_P(JwtHmacParametersTest, ParametersEquals) {
  int key_size_in_bytes;
  KidStrategyTuple tuple;
  JwtHmacParameters::Algorithm algorithm;
  std::tie(key_size_in_bytes, tuple, algorithm) = GetParam();

  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      key_size_in_bytes, tuple.kid_strategy, algorithm);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtHmacParameters> other_parameters =
      JwtHmacParameters::Create(key_size_in_bytes, tuple.kid_strategy,
                                algorithm);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(JwtHmacParametersTest, KeySizeNotEqual) {
  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/16,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtHmacParameters> other_parameters =
      JwtHmacParameters::Create(
          /*key_size_in_bytes=*/32,
          JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
          JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtHmacParametersTest, KidStrategyNotEqual) {
  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/16,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtHmacParameters> other_parameters =
      JwtHmacParameters::Create(
          /*key_size_in_bytes=*/16, JwtHmacParameters::KidStrategy::kCustom,
          JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtHmacParametersTest, AlgorithmNotEqual) {
  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/16,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtHmacParameters> other_parameters =
      JwtHmacParameters::Create(
          /*key_size_in_bytes=*/16,
          JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
          JwtHmacParameters::Algorithm::kHs384);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
