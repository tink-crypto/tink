// Copyright 2023 Google LLC
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

#include "tink/signature/rsa_ssa_pkcs1_public_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/partial_key_access.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
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
  int modulus_size_in_bits;
  RsaSsaPkcs1Parameters::HashType hash_type;
  RsaSsaPkcs1Parameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

// Test vector from
// https://github.com/google/wycheproof/blob/master/testvectors/rsa_pkcs1_2048_test.json
constexpr absl::string_view kHex2048BitRsaModulus =
    "00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628"
    "d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa"
    "3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861"
    "075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da386"
    "8e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca80"
    "59e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8"
    "647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d";

using RsaSsaPkcs1PublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1PublicKeyTestSuite, RsaSsaPkcs1PublicKeyTest,
    Values(TestCase{/*modulus_size=*/2048,
                    RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{/*modulus_size=*/2048,
                    RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{/*modulus_size=*/2048,
                    RsaSsaPkcs1Parameters::HashType::kSha384,
                    RsaSsaPkcs1Parameters::Variant::kLegacy,
                    /*id_requirement=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{/*modulus_size=*/2048,
                    RsaSsaPkcs1Parameters::HashType::kSha512,
                    RsaSsaPkcs1Parameters::Variant::kNoPrefix,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(RsaSsaPkcs1PublicKeyTest, CreatePublicKeySucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   test_case.id_requirement,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetModulus(GetPartialKeyAccess()), Eq(modulus));
}

TEST(RsaSsaPkcs1PublicKeyTest, CreateWithNonMatchingModulusSizeFails) {
  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Ed25519PublicKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  util::StatusOr<RsaSsaPkcs1Parameters> no_prefix_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_parameters, IsOk());

  util::StatusOr<RsaSsaPkcs1Parameters> tink_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));

  EXPECT_THAT(RsaSsaPkcs1PublicKey::Create(*no_prefix_parameters, modulus,
                                           /*id_requirement=*/123,
                                           GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(RsaSsaPkcs1PublicKey::Create(*tink_parameters, modulus,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(RsaSsaPkcs1PublicKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   test_case.id_requirement,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<RsaSsaPkcs1PublicKey> other_public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   test_case.id_requirement,
                                   GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(RsaSsaPkcs1PublicKeyTest, DifferentParametersNotEqual) {
  util::StatusOr<RsaSsaPkcs1Parameters> tink_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  util::StatusOr<RsaSsaPkcs1Parameters> crunchy_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(crunchy_parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*tink_parameters, modulus,
                                   /*id_requirement=*/0x02030400,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  util::StatusOr<RsaSsaPkcs1PublicKey> other_public_key =
      RsaSsaPkcs1PublicKey::Create(*crunchy_parameters, modulus,
                                   /*id_requirement=*/0x02030400,
                                   GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(RsaSsaPkcs1PublicKeyTest, DifferentModulusNotEqual) {
  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string other_modulus_bytes = absl::HexStringToBytes(
      "00dd904590397808c4314329623d9013453843251b13b8b3c4fef54598112af3eb31c711"
      "03c6259951674e53bd93a7e36d19472e474ebe8028686d9529484d8bafea4a04ba195556"
      "67616c8478670594009c9bc6a3efe52274cba64c724747d7edc194e4fedde32a3289d94c"
      "31936e7e7a15d756f548492f5b345b927e8c618bdd550acb21a17ae148304383db9b3c7b"
      "aa3e4c8bd8e844a884daa3e18d56998cb32f9bae4d41d56a18ddd4313c8089b75e9dbb91"
      "28470bac9b087fb61928ab0f8c4c89360b020899008d08e8bd31f907a807e8056ad6800d"
      "ffdf9ed9d964a939e7e48114b84978551acb85c9df9196f3eff55286d6cd4b39a822a8a7"
      "763a18208f");

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  BigInteger other_modulus(other_modulus_bytes);

  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  util::StatusOr<RsaSsaPkcs1PublicKey> other_public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, other_modulus,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(RsaSsaPkcs1PublicKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<RsaSsaPkcs1Parameters> tink_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*tink_parameters, modulus,
                                   /*id_requirement=*/0x02030400,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  util::StatusOr<RsaSsaPkcs1PublicKey> other_public_key =
      RsaSsaPkcs1PublicKey::Create(*tink_parameters, modulus,
                                   /*id_requirement=*/0x01020304,
                                   GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(RsaSsaPkcs1PublicKeyTest, PaddedWithZerosModulusEqual) {
  util::StatusOr<RsaSsaPkcs1Parameters> tink_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  BigInteger padded_with_zeros_modulus(
      absl::HexStringToBytes("000000" + std::string(kHex2048BitRsaModulus)));
  ASSERT_THAT(modulus, Eq(padded_with_zeros_modulus));

  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*tink_parameters, modulus,
                                   /*id_requirement=*/0x02030400,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<RsaSsaPkcs1PublicKey> other_public_key =
      RsaSsaPkcs1PublicKey::Create(*tink_parameters, padded_with_zeros_modulus,
                                   /*id_requirement=*/0x02030400,
                                   GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}
}  // namespace
}  // namespace tink
}  // namespace crypto
