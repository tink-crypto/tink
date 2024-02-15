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

#include "tink/aead/chacha20_poly1305_parameters.h"

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
using ::testing::IsTrue;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  ChaCha20Poly1305Parameters::Variant variant;
  bool has_id_requirement;
};

using ChaCha20Poly1305ParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    ChaCha20Poly1305ParametersTestSuite, ChaCha20Poly1305ParametersTest,
    Values(TestCase{ChaCha20Poly1305Parameters::Variant::kTink,
                    /*has_id_requirement=*/true},
           TestCase{ChaCha20Poly1305Parameters::Variant::kCrunchy,
                    /*has_id_requirement=*/true},
           TestCase{ChaCha20Poly1305Parameters::Variant::kNoPrefix,
                    /*has_id_requirement=*/false}));

TEST_P(ChaCha20Poly1305ParametersTest, Create) {
  TestCase test_case = GetParam();

  util::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(ChaCha20Poly1305ParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(ChaCha20Poly1305Parameters::Create(
                  ChaCha20Poly1305Parameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChaCha20Poly1305ParametersTest, CopyConstructor) {
  util::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  ChaCha20Poly1305Parameters copy(*parameters);
  EXPECT_THAT(copy.GetVariant(),
              Eq(ChaCha20Poly1305Parameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(ChaCha20Poly1305ParametersTest, CopyAssignment) {
  util::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  ChaCha20Poly1305Parameters copy = *parameters;
  EXPECT_THAT(copy.GetVariant(),
              Eq(ChaCha20Poly1305Parameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST_P(ChaCha20Poly1305ParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> other_parameters =
      ChaCha20Poly1305Parameters::Create(test_case.variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(ChaCha20Poly1305ParametersTest, DifferentVariantNotEqual) {
  util::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> other_parameters =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
