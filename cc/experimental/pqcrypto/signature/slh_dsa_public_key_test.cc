// Copyright 2024 Google LLC
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

#include "tink/experimental/pqcrypto/signature/slh_dsa_public_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  SlhDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using SlhDsaPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    SlhDsaPublicKeyTestSuite, SlhDsaPublicKeyTest,
    Values(TestCase{SlhDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{SlhDsaParameters::Variant::kTink, 0x03050709,
                    std::string("\x01\x03\x05\x07\x09", 5)},
           TestCase{SlhDsaParameters::Variant::kNoPrefix, absl::nullopt, ""}));

TEST_P(SlhDsaPublicKeyTest, CreatePublicKeyWorks) {
  TestCase test_case = GetParam();

  util::StatusOr<SlhDsaParameters> params = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);
  util::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*params, public_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(public_key_bytes));
}

TEST(SlhDsaPublicKeyTest, CreateWithInvalidPublicKeyLengthFails) {
  util::StatusOr<SlhDsaParameters> params = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(31);

  EXPECT_THAT(
      SlhDsaPublicKey::Create(*params, public_key_bytes,
                              /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid public key size")));
}

TEST(SlhDsaPublicKeyTest, CreateKeyWithNoIdRequirementWithTinkParamsFails) {
  util::StatusOr<SlhDsaParameters> tink_params = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  EXPECT_THAT(SlhDsaPublicKey::Create(*tink_params, public_key_bytes,
                                      /*id_requirement=*/absl::nullopt,
                                      GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key without ID requirement with parameters "
                                 "with ID requirement")));
}

TEST(SlhDsaPublicKeyTest, CreateKeyWithIdRequirementWithNoPrefixParamsFails) {
  util::StatusOr<SlhDsaParameters> no_prefix_params =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  EXPECT_THAT(
      SlhDsaPublicKey::Create(*no_prefix_params, public_key_bytes,
                              /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("key with ID requirement with parameters without ID "
                         "requirement")));
}

TEST_P(SlhDsaPublicKeyTest, PublicKeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<SlhDsaParameters> params = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*params, public_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<SlhDsaPublicKey> other_public_key =
      SlhDsaPublicKey::Create(*params, public_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(SlhDsaPublicKeyTest, DifferentPublicKeyBytesNotEqual) {
  util::StatusOr<SlhDsaParameters> params =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);

  std::string public_key_bytes1 = subtle::Random::GetRandomBytes(32);
  std::string public_key_bytes2 = subtle::Random::GetRandomBytes(32);

  util::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      *params, public_key_bytes1, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<SlhDsaPublicKey> other_public_key = SlhDsaPublicKey::Create(
      *params, public_key_bytes2, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(SlhDsaPublicKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<SlhDsaParameters> params =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<SlhDsaPublicKey> other_public_key = SlhDsaPublicKey::Create(
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
