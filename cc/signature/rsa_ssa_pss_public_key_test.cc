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

#include "tink/signature/rsa_ssa_pss_public_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/partial_key_access.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
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
  RsaSsaPssParameters::HashType hash_type;
  int salt_length_in_bytes;
  RsaSsaPssParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

// Test vector from
// https://github.com/google/wycheproof/blob/master/testvectors/rsa_pss_2048_sha256_mgf1_32_test.json
constexpr absl::string_view kHex2048BitRsaModulus =
    "00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d"
    "3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512e"
    "d8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a0"
    "29397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fc"
    "eca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1"
    "126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0"
    "f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d5";

using RsaSsaPssPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssPublicKeyTestSuite, RsaSsaPssPublicKeyTest,
    Values(
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha256,
                 /*salt_length_in_bytes*/ 0,
                 RsaSsaPssParameters::Variant::kTink,
                 /*id_requirement=*/0x02030400,
                 /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha256,
                 /*salt_length_in_bytes*/ 32,
                 RsaSsaPssParameters::Variant::kCrunchy,
                 /*id_requirement=*/0x01030005,
                 /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha384,
                 /*salt_length_in_bytes*/ 48,
                 RsaSsaPssParameters::Variant::kLegacy,
                 /*id_requirement=*/0x07080910,
                 /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha512,
                 /*salt_length_in_bytes*/ 64,
                 RsaSsaPssParameters::Variant::kNoPrefix,
                 /*id_requirement=*/absl::nullopt,
                 /*output_prefix=*/""}));

TEST_P(RsaSsaPssPublicKeyTest, CreatePublicKeySucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetModulus(GetPartialKeyAccess()), Eq(modulus));
}

TEST(RsaSsaPssPublicKeyTest, CreateWithNonMatchingModulusSizeFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Ed25519PublicKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  util::StatusOr<RsaSsaPssParameters> no_prefix_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_parameters, IsOk());

  util::StatusOr<RsaSsaPssParameters> tink_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));

  EXPECT_THAT(
      RsaSsaPssPublicKey::Create(*no_prefix_parameters, modulus,
                                 /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(RsaSsaPssPublicKey::Create(*tink_parameters, modulus,
                                         /*id_requirement=*/absl::nullopt,
                                         GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(RsaSsaPssPublicKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*parameters, modulus, test_case.id_requirement,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(RsaSsaPssPublicKeyTest, DifferentParametersNotEqual) {
  util::StatusOr<RsaSsaPssParameters> tink_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  util::StatusOr<RsaSsaPssParameters> crunchy_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(crunchy_parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *tink_parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  util::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*crunchy_parameters, modulus,
                                 /*id_requirement=*/0x02030400,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(RsaSsaPssPublicKeyTest, DifferentModulusNotEqual) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string other_modulus_bytes = absl::HexStringToBytes(
      "00c684aef47bc201764a663acdf22e67140410b3d201533b6ccaebf86eda3d81a1230a1c"
      "c5ce2c9e4e102d107f2418d9386f1d3734eb922629b4e7ef464f79fcac53744702a147c1"
      "ef8dafc8eb366284d3419d98e8cf176ccb7f65bada528c222956900e1ec0c2f21e83e3ee"
      "30d946a6aa267e01a28b9c1833b035a881ad1865dfd2a451086a46f38ed137237c5fe368"
      "261e3a46712399f3c56ac6fbde33682ba98c95e435e1dec2d5b9d681ade372622c2dbdbe"
      "47b419b4ba23a5defc3f792d4d8373cc27cf707dd2f3603363a0ffe643dcfda79758ad1a"
      "c53d46f1a5ec25df1ddd94780a8f51f88ffb32337f05395dec93267802db95243f1b62cc"
      "3dd8118d2d");

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  BigInteger other_modulus(other_modulus_bytes);

  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  util::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*parameters, other_modulus,
                                 /*id_requirement=*/absl::nullopt,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(RsaSsaPssPublicKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<RsaSsaPssParameters> tink_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *tink_parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  util::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*tink_parameters, modulus,
                                 /*id_requirement=*/0x01020304,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(RsaSsaPssPublicKeyTest, PaddedWithZerosModulusEqual) {
  util::StatusOr<RsaSsaPssParameters> tink_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  BigInteger modulus(absl::HexStringToBytes(kHex2048BitRsaModulus));
  BigInteger padded_with_zeros_modulus(
      absl::HexStringToBytes("000000" + std::string(kHex2048BitRsaModulus)));
  ASSERT_THAT(modulus, Eq(padded_with_zeros_modulus));

  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *tink_parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*tink_parameters, padded_with_zeros_modulus,
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
