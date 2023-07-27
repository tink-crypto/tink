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

#include "tink/signature/ed25519_parameters.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  Ed25519Parameters::Variant variant;
  bool has_id_requirement;
};

using Ed25519ParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(Ed25519ParametersTestSuite, Ed25519ParametersTest,
                         Values(TestCase{Ed25519Parameters::Variant::kTink,
                                         /*has_id_requirement=*/true},
                                TestCase{Ed25519Parameters::Variant::kCrunchy,
                                         /*has_id_requirement=*/true},
                                TestCase{Ed25519Parameters::Variant::kLegacy,
                                         /*has_id_requirement=*/true},
                                TestCase{Ed25519Parameters::Variant::kNoPrefix,
                                         /*has_id_requirement=*/false}));

TEST_P(Ed25519ParametersTest, Create) {
  TestCase test_case = GetParam();

  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(Ed25519ParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(Ed25519Parameters::Create(
                  Ed25519Parameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Ed25519ParametersTest, CopyConstructor) {
  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  Ed25519Parameters copy(*parameters);

  EXPECT_THAT(copy.GetVariant(), Eq(Ed25519Parameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(Ed25519ParametersTest, CopyAssignment) {
  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  Ed25519Parameters copy = *parameters;

  EXPECT_THAT(copy.GetVariant(), Eq(Ed25519Parameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST_P(Ed25519ParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<Ed25519Parameters> other_parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(Ed25519ParametersTest, VariantNotEqual) {
  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<Ed25519Parameters> other_parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
