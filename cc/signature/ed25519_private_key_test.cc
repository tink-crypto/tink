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

#include "tink/signature/ed25519_private_key.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ed25519_public_key.h"
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

using Ed25519PrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    Ed25519PrivateKeyTestSuite, Ed25519PrivateKeyTest,
    Values(TestCase{Ed25519Parameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{Ed25519Parameters::Variant::kCrunchy, 0x01030005,
                    std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{Ed25519Parameters::Variant::kLegacy, 0x07080910,
                    std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{Ed25519Parameters::Variant::kNoPrefix, absl::nullopt, ""}));

TEST_P(Ed25519PrivateKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*params, (*key_pair)->public_key,
                               test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes =
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get());

  util::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
}

TEST(Ed25519PrivateKeyTest, CreateWithMismatchedPublicKeyFails) {
  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);
  util::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*params, public_key_bytes,
                               /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes =
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(Ed25519PrivateKey::Create(*public_key, private_key_bytes,
                                        GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Ed25519PrivateKeyTest, CreateWithInvalidPrivateKeyLengthFails) {
  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*params, (*key_pair)->public_key,
                               /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes = RestrictedData(
      (*key_pair)->private_key.substr(0, 31), InsecureSecretKeyAccess::Get());

  EXPECT_THAT(Ed25519PrivateKey::Create(*public_key, private_key_bytes,
                                        GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(Ed25519PrivateKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*params, (*key_pair)->public_key,
                               test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes =
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get());

  util::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<Ed25519PrivateKey> other_private_key =
      Ed25519PrivateKey::Create(*public_key, private_key_bytes,
                                GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(Ed25519PrivateKeyTest, DifferentPublicKeyNotEqual) {
  util::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<Ed25519PublicKey> public_key123 =
      Ed25519PublicKey::Create(*params, (*key_pair)->public_key,
                               /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key123, IsOk());

  util::StatusOr<Ed25519PublicKey> public_key456 =
      Ed25519PublicKey::Create(*params, (*key_pair)->public_key,
                               /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(public_key456, IsOk());

  RestrictedData private_key_bytes =
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get());

  util::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key123, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<Ed25519PrivateKey> other_private_key =
      Ed25519PrivateKey::Create(*public_key456, private_key_bytes,
                                GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
