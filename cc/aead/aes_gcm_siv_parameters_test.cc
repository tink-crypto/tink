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

#include "tink/aead/aes_gcm_siv_parameters.h"

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

struct TestCase {
  AesGcmSivParameters::Variant variant;
  int key_size;
  bool has_id_requirement;
};

using AesGcmSivParametersCreateTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    AesGcmSivParametersCreateTestSuite, AesGcmSivParametersCreateTest,
    Values(TestCase{AesGcmSivParameters::Variant::kTink, /*key_size=*/16,
                    /*has_id_requirement=*/true},
           TestCase{AesGcmSivParameters::Variant::kCrunchy, /*key_size=*/32,
                    /*has_id_requirement=*/true},
           TestCase{AesGcmSivParameters::Variant::kNoPrefix,
                    /*key_size=*/32, /*has_id_requirement=*/false}));

TEST_P(AesGcmSivParametersCreateTest, Create) {
  TestCase test_case = GetParam();

  util::StatusOr<AesGcmSivParameters> parameters =
      AesGcmSivParameters::Create(test_case.key_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(AesGcmSivParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(AesGcmSivParameters::Create(
                  /*key_size_in_bytes=*/32,
                  AesGcmSivParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmSivParametersTest, CreateWithInvalidKeySizeFails) {
  EXPECT_THAT(
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/15,
                                  AesGcmSivParameters::Variant::kNoPrefix)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/17,
                                  AesGcmSivParameters::Variant::kNoPrefix)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/31,
                                  AesGcmSivParameters::Variant::kNoPrefix)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/33,
                                  AesGcmSivParameters::Variant::kNoPrefix)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmParametersTest, CopyConstructor) {
  util::StatusOr<AesGcmSivParameters> parameters = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/16, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  AesGcmSivParameters copy(*parameters);
  EXPECT_THAT(copy.KeySizeInBytes(), Eq(16));
  EXPECT_THAT(copy.GetVariant(), Eq(AesGcmSivParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(AesGcmParametersTest, CopyAssignment) {
  util::StatusOr<AesGcmSivParameters> parameters = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  AesGcmSivParameters copy = *parameters;
  EXPECT_THAT(copy.KeySizeInBytes(), Eq(32));
  EXPECT_THAT(copy.GetVariant(), Eq(AesGcmSivParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

using AesGcmSivParametersVariantTest =
    TestWithParam<std::tuple<int, AesGcmSivParameters::Variant>>;

INSTANTIATE_TEST_SUITE_P(
    AesGcmSivParametersVariantTestSuite, AesGcmSivParametersVariantTest,
    Combine(Values(16, 32), Values(AesGcmSivParameters::Variant::kTink,
                                   AesGcmSivParameters::Variant::kCrunchy,
                                   AesGcmSivParameters::Variant::kNoPrefix)));

TEST_P(AesGcmSivParametersVariantTest, ParametersEquals) {
  int key_size;
  AesGcmSivParameters::Variant variant;
  std::tie(key_size, variant) = GetParam();

  util::StatusOr<AesGcmSivParameters> parameters =
      AesGcmSivParameters::Create(key_size, variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesGcmSivParameters> other_parameters =
      AesGcmSivParameters::Create(key_size, variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(AesGcmParametersTest, KeySizeNotEqual) {
  util::StatusOr<AesGcmSivParameters> parameters = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/16, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesGcmSivParameters> other_parameters =
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/32,
                                  AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesGcmParametersTest, VariantNotEqual) {
  util::StatusOr<AesGcmSivParameters> parameters = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesGcmSivParameters> other_parameters =
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/32,
                                  AesGcmSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
