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

#include "tink/daead/aes_siv_parameters.h"

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
using ::testing::IsTrue;
using ::testing::TestWithParam;
using ::testing::Values;

struct CreateTestCase {
  AesSivParameters::Variant variant;
  int key_size;
  bool has_id_requirement;
};

using AesSivParametersBuildTest = TestWithParam<CreateTestCase>;

INSTANTIATE_TEST_SUITE_P(
    AesSivParametersBuildTestSuite, AesSivParametersBuildTest,
    Values(CreateTestCase{AesSivParameters::Variant::kTink, /*key_size=*/32,
                          /*has_id_requirement=*/true},
           CreateTestCase{AesSivParameters::Variant::kCrunchy, /*key_size=*/48,
                          /*has_id_requirement=*/true},
           CreateTestCase{AesSivParameters::Variant::kNoPrefix, /*key_size=*/64,
                          /*has_id_requirement=*/false}));

TEST_P(AesSivParametersBuildTest, Create) {
  CreateTestCase test_case = GetParam();

  util::StatusOr<AesSivParameters> parameters =
      AesSivParameters::Create(test_case.key_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(AesSivParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(AesSivParameters::Create(
                  /*key_size_in_bytes=*/64,
                  AesSivParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesSivParametersTest, CreateWithInvalidKeySizeFails) {
  EXPECT_THAT(AesSivParameters::Create(/*key_size_in_bytes=*/31,
                                       AesSivParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesSivParameters::Create(/*key_size_in_bytes=*/33,
                                       AesSivParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesSivParameters::Create(/*key_size_in_bytes=*/47,
                                       AesSivParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesSivParameters::Create(/*key_size_in_bytes=*/49,
                                       AesSivParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesSivParameters::Create(/*key_size_in_bytes=*/63,
                                       AesSivParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesSivParameters::Create(/*key_size_in_bytes=*/65,
                                       AesSivParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesSivParametersTest, CopyConstructor) {
  util::StatusOr<AesSivParameters> parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  AesSivParameters copy(*parameters);
  EXPECT_THAT(copy.KeySizeInBytes(), Eq(64));
  EXPECT_THAT(copy.GetVariant(), Eq(AesSivParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(AesSivParametersTest, CopyAssignment) {
  util::StatusOr<AesSivParameters> parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  AesSivParameters copy = *parameters;
  EXPECT_THAT(copy.KeySizeInBytes(), Eq(64));
  EXPECT_THAT(copy.GetVariant(), Eq(AesSivParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

using AesSivParametersVariantTest =
    TestWithParam<std::tuple<int, AesSivParameters::Variant>>;

INSTANTIATE_TEST_SUITE_P(AesSivParametersVariantTestSuite,
                         AesSivParametersVariantTest,
                         Combine(Values(32, 48, 64),
                                 Values(AesSivParameters::Variant::kTink,
                                        AesSivParameters::Variant::kCrunchy,
                                        AesSivParameters::Variant::kNoPrefix)));

TEST_P(AesSivParametersVariantTest, ParametersEquals) {
  int key_size;
  AesSivParameters::Variant variant;
  std::tie(key_size, variant) = GetParam();

  util::StatusOr<AesSivParameters> parameters =
      AesSivParameters::Create(key_size, variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesSivParameters> other_parameters =
      AesSivParameters::Create(key_size, variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(AesSivParametersTest, KeySizeNotEqual) {
  util::StatusOr<AesSivParameters> parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/48, AesSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesSivParameters> other_parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesSivParametersTest, VariantNotEqual) {
  util::StatusOr<AesSivParameters> parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesSivParameters> other_parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
