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

#include "tink/aead/aes_eax_parameters.h"

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
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

struct BuildTestCase {
  int key_size;
  int iv_size;
  int tag_size;
  AesEaxParameters::Variant variant;
  bool has_id_requirement;
};

using AesEaxParametersTest = TestWithParam<BuildTestCase>;

INSTANTIATE_TEST_SUITE_P(
    AesEaxParametersBuildTestSuite, AesEaxParametersTest,
    Values(BuildTestCase{/*key_size=*/16,
                         /*iv_size=*/12, /*tag_size=*/12,
                         AesEaxParameters::Variant::kTink,
                         /*has_id_requirement=*/true},
           BuildTestCase{/*key_size=*/24,
                         /*iv_size=*/16, /*tag_size=*/14,
                         AesEaxParameters::Variant::kCrunchy,
                         /*has_id_requirement=*/true},
           BuildTestCase{/*key_size=*/32, /*iv_size=*/16, /*tag_size=*/16,
                         AesEaxParameters::Variant::kNoPrefix,
                         /*has_id_requirement=*/false}));

TEST_P(AesEaxParametersTest, BuildParametersSucceeds) {
  BuildTestCase test_case = GetParam();

  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetKeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->GetIvSizeInBytes(), Eq(test_case.iv_size));
  EXPECT_THAT(parameters->GetTagSizeInBytes(), Eq(test_case.tag_size));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(AesEaxParametersTest, BuildWithoutSettingVariantFails) {
  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesEaxParametersTest, BuildWithInvalidVariantFails) {
  EXPECT_THAT(
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesEaxParametersTest, BuildWithoutSettingKeySizeFails) {
  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesEaxParametersTest, BuildWithInvalidKeySizeFails) {
  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(15)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(17)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(23)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(25)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(31)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(33)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesEaxParametersTest, BuildWithoutSettingIvSizeFails) {
  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesEaxParametersTest, BuildWithInvalidIvSizeFails) {
  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(11)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(13)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(11)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(13)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(15)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(17)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesEaxParametersTest, BuildWithoutSettingTagSizeFails) {
  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesEaxParametersTest, BuildWithInvalidTagSizeFails) {
  // Negative value.
  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(-16)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Too big.
  EXPECT_THAT(AesEaxParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(17)
                  .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesEaxParametersTest, CopyConstructor) {
  BuildTestCase test_case = GetParam();

  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesEaxParameters copy(*parameters);
  EXPECT_THAT(copy.GetKeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(copy.GetIvSizeInBytes(), Eq(test_case.iv_size));
  EXPECT_THAT(copy.GetTagSizeInBytes(), Eq(test_case.tag_size));
  EXPECT_THAT(copy.GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(copy.HasIdRequirement(), test_case.has_id_requirement);
}

TEST_P(AesEaxParametersTest, CopyAssignment) {
  BuildTestCase test_case = GetParam();

  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesEaxParameters copy = *parameters;
  EXPECT_THAT(copy.GetKeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(copy.GetIvSizeInBytes(), Eq(test_case.iv_size));
  EXPECT_THAT(copy.GetTagSizeInBytes(), Eq(test_case.tag_size));
  EXPECT_THAT(copy.GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(copy.HasIdRequirement(), test_case.has_id_requirement);
}

TEST_P(AesEaxParametersTest, SameParametersEquals) {
  BuildTestCase test_case = GetParam();

  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesEaxParameters> other_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(AesEaxParametersTest, DifferentKeySizeNotEqual) {
  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesEaxParameters> other_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(24)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesEaxParametersTest, DifferentIvSizeNotEqual) {
  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesEaxParameters> other_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesEaxParametersTest, DifferentTagSizeNotEqual) {
  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(14)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesEaxParameters> other_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesEaxParametersTest, DifferentVariantNotEqual) {
  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesEaxParameters> other_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
