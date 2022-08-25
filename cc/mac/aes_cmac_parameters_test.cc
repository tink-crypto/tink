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

#include "tink/mac/aes_cmac_parameters.h"

#include <memory>
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
using ::testing::Range;
using ::testing::TestWithParam;
using ::testing::Values;

struct CreateTestCase {
  AesCmacParameters::Variant variant;
  int key_size;
  int cryptographic_tag_size;
  int total_tag_size;
  bool has_id_requirement;
};

using AesCmacParametersCreateTest = TestWithParam<CreateTestCase>;

INSTANTIATE_TEST_SUITE_P(
    AesCmacParametersCreateTestSuite, AesCmacParametersCreateTest,
    Values(CreateTestCase{AesCmacParameters::Variant::kTink, /*key_size=*/16,
                          /*cryptographic_tag_size=*/10, /*total_tag_size=*/15,
                          /*has_id_requirement=*/true},
           CreateTestCase{AesCmacParameters::Variant::kCrunchy, /*key_size=*/16,
                          /*cryptographic_tag_size=*/12, /*total_tag_size=*/17,
                          /*has_id_requirement=*/true},
           CreateTestCase{AesCmacParameters::Variant::kLegacy, /*key_size=*/32,
                          /*cryptographic_tag_size=*/14, /*total_tag_size=*/19,
                          /*has_id_requirement=*/true},
           CreateTestCase{AesCmacParameters::Variant::kNoPrefix,
                          /*key_size=*/32, /*cryptographic_tag_size=*/16,
                          /*total_tag_size=*/16,
                          /*has_id_requirement=*/false}));

TEST_P(AesCmacParametersCreateTest, Create) {
  CreateTestCase test_case = GetParam();

  util::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      test_case.key_size, test_case.cryptographic_tag_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->CryptographicTagSizeInBytes(),
              Eq(test_case.cryptographic_tag_size));
  EXPECT_THAT(parameters->TotalTagSizeInBytes(), Eq(test_case.total_tag_size));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(AesCmacParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(AesCmacParameters::Create(
                  /*key_size_in_bytes=*/32,
                  /*cryptographic_tag_size_in_bytes=*/12,
                  AesCmacParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCmacParametersTest, CreateWithInvalidKeySizeFails) {
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/15,
                                        /*cryptographic_tag_size_in_bytes=*/16,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/17,
                                        /*cryptographic_tag_size_in_bytes=*/16,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/31,
                                        /*cryptographic_tag_size_in_bytes=*/16,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/33,
                                        /*cryptographic_tag_size_in_bytes=*/16,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCmacParametersTest, CreateWithInvalidTagSizeFails) {
  // Too small.
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                        /*cryptographic_tag_size_in_bytes=*/7,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                        /*cryptographic_tag_size_in_bytes=*/8,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                        /*cryptographic_tag_size_in_bytes=*/9,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  // Too big;
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                        /*cryptographic_tag_size_in_bytes=*/17,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                        /*cryptographic_tag_size_in_bytes=*/18,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                        /*cryptographic_tag_size_in_bytes=*/19,
                                        AesCmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCmacParametersTest, CopyConstructor) {
  util::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/12,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  AesCmacParameters copy(*parameters);
  EXPECT_THAT(copy.GetVariant(), Eq(parameters->GetVariant()));
  EXPECT_THAT(copy.CryptographicTagSizeInBytes(),
              Eq(parameters->CryptographicTagSizeInBytes()));
  EXPECT_THAT(copy.TotalTagSizeInBytes(),
              Eq(parameters->TotalTagSizeInBytes()));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(parameters->HasIdRequirement()));
}

TEST(AesCmacParametersTest, CopyAssignment) {
  util::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/12,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  AesCmacParameters copy = *parameters;
  EXPECT_THAT(copy.GetVariant(), Eq(parameters->GetVariant()));
  EXPECT_THAT(copy.CryptographicTagSizeInBytes(),
              Eq(parameters->CryptographicTagSizeInBytes()));
  EXPECT_THAT(copy.TotalTagSizeInBytes(),
              Eq(parameters->TotalTagSizeInBytes()));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(parameters->HasIdRequirement()));
}

using AesCmacParametersVariantTest =
    TestWithParam<std::tuple<int, int, AesCmacParameters::Variant>>;

INSTANTIATE_TEST_SUITE_P(
    AesCmacParametersVariantTestSuite, AesCmacParametersVariantTest,
    Combine(Values(16, 32), Range(10, 16),
            Values(AesCmacParameters::Variant::kTink,
                   AesCmacParameters::Variant::kCrunchy,
                   AesCmacParameters::Variant::kLegacy,
                   AesCmacParameters::Variant::kNoPrefix)));

TEST_P(AesCmacParametersVariantTest, ParametersEquals) {
  int key_size;
  int cryptographic_tag_size;
  AesCmacParameters::Variant variant;
  std::tie(key_size, cryptographic_tag_size, variant) = GetParam();

  util::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(key_size, cryptographic_tag_size, variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesCmacParameters> other_parameters =
      AesCmacParameters::Create(key_size, cryptographic_tag_size, variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(AesCmacParametersTest, KeySizeNotEqual) {
  util::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/16,
                                /*cryptographic_tag_size_in_bytes=*/10,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesCmacParameters> other_parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/10,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCmacParametersTest, TagSizeNotEqual) {
  util::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/10,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesCmacParameters> other_parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/11,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCmacParametersTest, VariantNotEqual) {
  util::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/10,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesCmacParameters> other_parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/10,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
