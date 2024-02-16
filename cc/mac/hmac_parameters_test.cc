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

#include "tink/mac/hmac_parameters.h"

#include <memory>
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
using ::testing::Range;
using ::testing::TestWithParam;
using ::testing::Values;

struct CreateTestCase {
  HmacParameters::Variant variant;
  int key_size;
  int cryptographic_tag_size;
  int total_tag_size;
  HmacParameters::HashType hash_type;
  bool has_id_requirement;
};

using HmacParametersCreateTest = TestWithParam<CreateTestCase>;

INSTANTIATE_TEST_SUITE_P(
    HmacParametersCreateTestSuite, HmacParametersCreateTest,
    Values(CreateTestCase{HmacParameters::Variant::kNoPrefix, /*key_size=*/16,
                          /*cryptographic_tag_size=*/20, /*total_tag_size=*/20,
                          HmacParameters::HashType::kSha1,
                          /*has_id_requirement=*/false},
           CreateTestCase{HmacParameters::Variant::kTink, /*key_size=*/16,
                          /*cryptographic_tag_size=*/28, /*total_tag_size=*/33,
                          HmacParameters::HashType::kSha224,
                          /*has_id_requirement=*/true},
           CreateTestCase{HmacParameters::Variant::kCrunchy, /*key_size=*/16,
                          /*cryptographic_tag_size=*/32, /*total_tag_size=*/37,
                          HmacParameters::HashType::kSha256,
                          /*has_id_requirement=*/true},
           CreateTestCase{HmacParameters::Variant::kLegacy, /*key_size=*/32,
                          /*cryptographic_tag_size=*/48, /*total_tag_size=*/53,
                          HmacParameters::HashType::kSha384,
                          /*has_id_requirement=*/true},
           CreateTestCase{HmacParameters::Variant::kNoPrefix,
                          /*key_size=*/32, /*cryptographic_tag_size=*/64,
                          /*total_tag_size=*/64,
                          HmacParameters::HashType::kSha512,
                          /*has_id_requirement=*/false}));

TEST_P(HmacParametersCreateTest, Create) {
  CreateTestCase test_case = GetParam();

  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      test_case.key_size, test_case.cryptographic_tag_size, test_case.hash_type,
      test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->CryptographicTagSizeInBytes(),
              Eq(test_case.cryptographic_tag_size));
  EXPECT_THAT(parameters->TotalTagSizeInBytes(), Eq(test_case.total_tag_size));
  EXPECT_THAT(parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(HmacParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(HmacParameters::Create(
                  /*key_size_in_bytes=*/16,
                  /*cryptographic_tag_size_in_bytes=*/12,
                  HmacParameters::HashType::kSha256,
                  HmacParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HmacParametersTest, CreateWithInvalidHashTypeFails) {
  EXPECT_THAT(HmacParameters::Create(
                  /*key_size_in_bytes=*/32,
                  /*cryptographic_tag_size_in_bytes=*/12,
                  HmacParameters::HashType::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  HmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HmacParametersTest, CreateWithInvalidKeySizeFails) {
  EXPECT_THAT(HmacParameters::Create(/*key_size_in_bytes=*/15,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     HmacParameters::HashType::kSha256,
                                     HmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HmacParametersTest, CreateWithInvalidTagSizeFails) {
  // Too small.
  EXPECT_THAT(HmacParameters::Create(/*key_size_in_bytes=*/32,
                                     /*cryptographic_tag_size_in_bytes=*/7,
                                     HmacParameters::HashType::kSha224,
                                     HmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  // Too big for kSha1.
  EXPECT_THAT(HmacParameters::Create(/*key_size_in_bytes=*/32,
                                     /*cryptographic_tag_size_in_bytes=*/21,
                                     HmacParameters::HashType::kSha1,
                                     HmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  // Too big for kSha224.
  EXPECT_THAT(HmacParameters::Create(/*key_size_in_bytes=*/32,
                                     /*cryptographic_tag_size_in_bytes=*/29,
                                     HmacParameters::HashType::kSha224,
                                     HmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  // Too big for kSha256;
  EXPECT_THAT(HmacParameters::Create(/*key_size_in_bytes=*/32,
                                     /*cryptographic_tag_size_in_bytes=*/33,
                                     HmacParameters::HashType::kSha256,
                                     HmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  // Too big for kSha384;
  EXPECT_THAT(HmacParameters::Create(/*key_size_in_bytes=*/32,
                                     /*cryptographic_tag_size_in_bytes=*/49,
                                     HmacParameters::HashType::kSha384,
                                     HmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  // Too big for kSha512;
  EXPECT_THAT(HmacParameters::Create(/*key_size_in_bytes=*/32,
                                     /*cryptographic_tag_size_in_bytes=*/65,
                                     HmacParameters::HashType::kSha512,
                                     HmacParameters::Variant::kNoPrefix)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HmacParametersTest, CopyConstructor) {
  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/12, HmacParameters::HashType::kSha256,
      HmacParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  HmacParameters copy(*parameters);
  EXPECT_THAT(copy.GetVariant(), Eq(parameters->GetVariant()));
  EXPECT_THAT(copy.CryptographicTagSizeInBytes(),
              Eq(parameters->CryptographicTagSizeInBytes()));
  EXPECT_THAT(copy.TotalTagSizeInBytes(),
              Eq(parameters->TotalTagSizeInBytes()));
  EXPECT_THAT(copy.GetHashType(), Eq(parameters->GetHashType()));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(parameters->HasIdRequirement()));
}

TEST(HmacParametersTest, CopyAssignment) {
  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/12, HmacParameters::HashType::kSha512,
      HmacParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  HmacParameters copy = *parameters;
  EXPECT_THAT(copy.GetVariant(), Eq(parameters->GetVariant()));
  EXPECT_THAT(copy.CryptographicTagSizeInBytes(),
              Eq(parameters->CryptographicTagSizeInBytes()));
  EXPECT_THAT(copy.TotalTagSizeInBytes(),
              Eq(parameters->TotalTagSizeInBytes()));
  EXPECT_THAT(copy.GetHashType(), Eq(parameters->GetHashType()));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(parameters->HasIdRequirement()));
}

using HmacParametersVariantTest = TestWithParam<
    std::tuple<int, int, HmacParameters::HashType, HmacParameters::Variant>>;

INSTANTIATE_TEST_SUITE_P(HmacParametersVariantTestSuite,
                         HmacParametersVariantTest,
                         Combine(Range(16, 32), Range(10, 20),
                                 Values(HmacParameters::HashType::kSha1,
                                        HmacParameters::HashType::kSha224,
                                        HmacParameters::HashType::kSha256,
                                        HmacParameters::HashType::kSha384,
                                        HmacParameters::HashType::kSha512),
                                 Values(HmacParameters::Variant::kTink,
                                        HmacParameters::Variant::kCrunchy,
                                        HmacParameters::Variant::kLegacy,
                                        HmacParameters::Variant::kNoPrefix)));

TEST_P(HmacParametersVariantTest, ParametersEquals) {
  int key_size;
  int cryptographic_tag_size;
  HmacParameters::HashType hash_type;
  HmacParameters::Variant variant;
  std::tie(key_size, cryptographic_tag_size, hash_type, variant) = GetParam();

  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      key_size, cryptographic_tag_size, hash_type, variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HmacParameters> other_parameters = HmacParameters::Create(
      key_size, cryptographic_tag_size, hash_type, variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(HmacParametersTest, KeySizeNotEqual) {
  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/16,
      /*cryptographic_tag_size_in_bytes=*/10, HmacParameters::HashType::kSha224,
      HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HmacParameters> other_parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/10, HmacParameters::HashType::kSha224,
      HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HmacParametersTest, HashTypeNotEqual) {
  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/10, HmacParameters::HashType::kSha256,
      HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HmacParameters> other_parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/10, HmacParameters::HashType::kSha512,
      HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HmacParametersTest, TagSizeNotEqual) {
  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/10, HmacParameters::HashType::kSha256,
      HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HmacParameters> other_parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/11, HmacParameters::HashType::kSha256,
      HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HmacParametersTest, VariantNotEqual) {
  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/10, HmacParameters::HashType::kSha256,
      HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HmacParameters> other_parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/10, HmacParameters::HashType::kSha256,
      HmacParameters::Variant::kTink);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
