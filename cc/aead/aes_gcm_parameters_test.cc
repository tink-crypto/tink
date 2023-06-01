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

#include "tink/aead/aes_gcm_parameters.h"

#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
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
using ::testing::Range;
using ::testing::TestWithParam;
using ::testing::Values;

struct BuildTestCase {
  AesGcmParameters::Variant variant;
  int key_size;
  int iv_size;
  int tag_size;
  bool has_id_requirement;
};

using AesGcmParametersBuildTest = TestWithParam<BuildTestCase>;

INSTANTIATE_TEST_SUITE_P(
    AesGcmParametersBuildTestSuite, AesGcmParametersBuildTest,
    Values(BuildTestCase{AesGcmParameters::Variant::kTink, /*key_size=*/16,
                         /*iv_size=*/12, /*tag_size=*/12,
                         /*has_id_requirement=*/true},
           BuildTestCase{AesGcmParameters::Variant::kCrunchy, /*key_size=*/24,
                         /*iv_size=*/14, /*tag_size=*/14,
                         /*has_id_requirement=*/true},
           BuildTestCase{AesGcmParameters::Variant::kNoPrefix,
                         /*key_size=*/32, /*iv_size=*/16, /*tag_size=*/16,
                         /*has_id_requirement=*/false}));

TEST_P(AesGcmParametersBuildTest, Build) {
  BuildTestCase test_case = GetParam();

  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->IvSizeInBytes(), Eq(test_case.iv_size));
  EXPECT_THAT(parameters->TagSizeInBytes(), Eq(test_case.tag_size));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(AesGcmParametersTest, BuildWithoutSettingVariantFails) {
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmParametersTest, BuildWithInvalidVariantFails) {
  EXPECT_THAT(
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmParametersTest, BuildWithoutSettingKeySizeFails) {
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmParametersTest, BuildWithInvalidKeySizeFails) {
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(15)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(17)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(23)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(25)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(31)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(33)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmParametersTest, BuildWithoutSettingIvSizeFails) {
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmParametersTest, BuildWithInvalidIvSizeFails) {
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(0)
                  .SetTagSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmParametersTest, BuildWithoutSettingTagSizeFails) {
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmParametersTest, BuildWithInvalidTagSizeFails) {
  // Too small.
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(11)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  // Too big.
  EXPECT_THAT(AesGcmParameters::Builder()
                  .SetKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(17)
                  .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmParametersTest, CopyConstructor) {
  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesGcmParameters copy(*parameters);
  EXPECT_THAT(copy.KeySizeInBytes(), Eq(16));
  EXPECT_THAT(copy.IvSizeInBytes(), Eq(16));
  EXPECT_THAT(copy.TagSizeInBytes(), Eq(16));
  EXPECT_THAT(copy.GetVariant(), Eq(AesGcmParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(AesGcmParametersTest, CopyAssignment) {
  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesGcmParameters copy = *parameters;
  EXPECT_THAT(copy.KeySizeInBytes(), Eq(16));
  EXPECT_THAT(copy.IvSizeInBytes(), Eq(16));
  EXPECT_THAT(copy.TagSizeInBytes(), Eq(16));
  EXPECT_THAT(copy.GetVariant(), Eq(AesGcmParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

using AesGcmParametersVariantTest =
    TestWithParam<std::tuple<int, int, AesGcmParameters::Variant>>;

INSTANTIATE_TEST_SUITE_P(AesGcmParametersVariantTestSuite,
                         AesGcmParametersVariantTest,
                         Combine(Values(16, 24, 32), Range(12, 16),
                                 Values(AesGcmParameters::Variant::kTink,
                                        AesGcmParameters::Variant::kCrunchy,
                                        AesGcmParameters::Variant::kNoPrefix)));

TEST_P(AesGcmParametersVariantTest, ParametersEquals) {
  int key_size;
  int iv_and_tag_size;
  AesGcmParameters::Variant variant;
  std::tie(key_size, iv_and_tag_size, variant) = GetParam();

  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(key_size)
          .SetIvSizeInBytes(iv_and_tag_size)
          .SetTagSizeInBytes(iv_and_tag_size)
          .SetVariant(variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesGcmParameters> other_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(key_size)
          .SetIvSizeInBytes(iv_and_tag_size)
          .SetTagSizeInBytes(iv_and_tag_size)
          .SetVariant(variant)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(AesGcmParametersTest, KeySizeNotEqual) {
  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesGcmParameters> other_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(24)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesGcmParametersTest, IvSizeNotEqual) {
  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesGcmParameters> other_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesGcmParametersTest, TagSizeNotEqual) {
  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesGcmParameters> other_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(14)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesGcmParametersTest, VariantNotEqual) {
  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesGcmParameters> other_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
