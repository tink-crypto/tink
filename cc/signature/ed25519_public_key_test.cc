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

#include "tink/signature/ed25519_public_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/subtle/random.h"
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

struct TestCase {
  Ed25519Parameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using Ed25519PublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    Ed25519PublicKeyTestSuite, Ed25519PublicKeyTest,
    Values(TestCase{Ed25519Parameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{Ed25519Parameters::Variant::kCrunchy, 0x01030005,
                    std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{Ed25519Parameters::Variant::kLegacy, 0x07080910,
                    std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{Ed25519Parameters::Variant::kNoPrefix, absl::nullopt, ""}));

TEST_P(Ed25519PublicKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);
  util::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*params, public_key_bytes,
                               test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(public_key_bytes));
}

TEST(Ed25519PublicKeyTest, CreateWithInvalidPublicKeyLength) {
  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(31);

  EXPECT_THAT(
      Ed25519PublicKey::Create(*params, public_key_bytes,
                               /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Ed25519PublicKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  util::StatusOr<Ed25519Parameters> no_prefix_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());

  util::StatusOr<Ed25519Parameters> tink_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  EXPECT_THAT(
      Ed25519PublicKey::Create(*no_prefix_params, public_key_bytes,
                               /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(Ed25519PublicKey::Create(*tink_params, public_key_bytes,
                                       /*id_requirement=*/absl::nullopt,
                                       GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(Ed25519PublicKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*params, public_key_bytes,
                               test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<Ed25519PublicKey> other_public_key =
      Ed25519PublicKey::Create(*params, public_key_bytes,
                               test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(Ed25519PublicKeyTest, DifferentVariantNotEqual) {
  util::StatusOr<Ed25519Parameters> crunchy_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kCrunchy);
  ASSERT_THAT(crunchy_params, IsOk());

  util::StatusOr<Ed25519Parameters> tink_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *crunchy_params, public_key_bytes, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<Ed25519PublicKey> other_public_key = Ed25519PublicKey::Create(
      *tink_params, public_key_bytes, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Ed25519PublicKeyTest, DifferentPublicKeyBytesNotEqual) {
  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes1 = subtle::Random::GetRandomBytes(32);
  std::string public_key_bytes2 = subtle::Random::GetRandomBytes(32);

  util::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, public_key_bytes1, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<Ed25519PublicKey> other_public_key = Ed25519PublicKey::Create(
      *params, public_key_bytes2, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Ed25519PublicKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<Ed25519PublicKey> other_public_key = Ed25519PublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/0x02030405,
      GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
