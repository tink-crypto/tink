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

#include "tink/signature/rsa_ssa_pss_parameters.h"

#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#else
#include "openssl/bn.h"
#endif
#include "tink/big_integer.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
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
  int modulus_size_in_bits;
  RsaSsaPssParameters::HashType hash_type;
  RsaSsaPssParameters::Variant variant;
  int salt_length_in_bytes;
  bool has_id_requirement;
};

using RsaSsaPssParametersTest = TestWithParam<TestCase>;

std::string PublicExponentToString(int64_t public_exponent) {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);

  return internal::BignumToString(e.get(), BN_num_bytes(e.get())).value();
}

const BigInteger& kF4 = *(new BigInteger(PublicExponentToString(65537)));

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssParametersTestSuite, RsaSsaPssParametersTest,
    Values(
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha256,
                 RsaSsaPssParameters::Variant::kTink,
                 /*salt_length_in_bytes*/ 32,
                 /*has_id_requirement=*/true},
        TestCase{/*modulus_size=*/3072, RsaSsaPssParameters::HashType::kSha256,
                 RsaSsaPssParameters::Variant::kCrunchy,
                 /*salt_length_in_bytes*/ 32,
                 /*has_id_requirement=*/true},
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha384,
                 RsaSsaPssParameters::Variant::kLegacy,
                 /*salt_length_in_bytes*/ 48,
                 /*has_id_requirement=*/true},
        TestCase{/*modulus_size=*/3072, RsaSsaPssParameters::HashType::kSha512,
                 RsaSsaPssParameters::Variant::kNoPrefix,
                 /*salt_length_in_bytes*/ 64,
                 /*has_id_requirement=*/false}));

TEST_P(RsaSsaPssParametersTest, Build) {
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

  EXPECT_THAT(parameters->GetModulusSizeInBits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetSigHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(parameters->GetMgf1HashType(), Eq(test_case.hash_type));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(RsaSsaPssParametersTest, BuildWithInvalidVariantFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithoutVariantFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithInvalidSigHashTypeFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(
              RsaSsaPssParameters::HashType::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithInvalidMgf1gHashTypeFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(
              RsaSsaPssParameters::HashType::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithDifferentSigAndMgf1HashTypesFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
          .SetSaltLengthInBytes(48)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithoutSigHashTypeFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(64)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithoutMgf1HashTypeFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(64)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithLargeModulusSizeWorks) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(16789)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(16789));
}

TEST(RsaSsaPssParametersTest, BuildWithTooSmallModulusSizeFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2047)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithoutModulusSizeFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithoutSaltLengthFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithNegativeSaltLengthFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(-32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithValidNonF4PublicExponent) {
  BigInteger nonF4_public_exponent =
      BigInteger(PublicExponentToString(1234567));
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(nonF4_public_exponent)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(nonF4_public_exponent));
}

TEST(RsaSsaPssParametersTest, BuildWithoutPublicExponentDefaultsToF4) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
}

TEST(RsaSsaPssParametersTest, BuildWithSmallPublicExponentFails) {
  BigInteger small_public_exponent = BigInteger(PublicExponentToString(3));
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(small_public_exponent)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithEvenPublicExponentFails) {
  BigInteger even_public_exponent = BigInteger(PublicExponentToString(123456));
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(even_public_exponent)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, BuildWithLargePublicExponent) {
  BigInteger large_public_exponent =
      BigInteger(PublicExponentToString(100000001L));
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(large_public_exponent)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(large_public_exponent));
}

TEST(RsaSsaPssParametersTest, BuildWithTooLargePublicExponent) {
  // Public exponent must be smaller than 32 bits.
  BigInteger too_large_public_exponent =
      BigInteger(PublicExponentToString(4294967297L));
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(too_large_public_exponent)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssParametersTest, CopyConstructor) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(64)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RsaSsaPssParameters copy(*parameters);

  EXPECT_THAT(copy.GetVariant(), Eq(RsaSsaPssParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetSigHashType(),
              Eq(RsaSsaPssParameters::HashType::kSha512));
  EXPECT_THAT(parameters->GetMgf1HashType(),
              Eq(RsaSsaPssParameters::HashType::kSha512));
  EXPECT_THAT(parameters->GetSaltLengthInBytes(), Eq(64));
}

TEST(RsaSsaPssParametersTest, CopyAssignment) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(64)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RsaSsaPssParameters copy = *parameters;

  EXPECT_THAT(copy.GetVariant(), Eq(RsaSsaPssParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetSigHashType(),
              Eq(RsaSsaPssParameters::HashType::kSha512));
  EXPECT_THAT(parameters->GetMgf1HashType(),
              Eq(RsaSsaPssParameters::HashType::kSha512));
  EXPECT_THAT(parameters->GetSaltLengthInBytes(), Eq(64));
}

TEST_P(RsaSsaPssParametersTest, ParametersEquals) {
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

  util::StatusOr<RsaSsaPssParameters> other_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(RsaSsaPssParametersTest, VariantNotEqual) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(64)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<RsaSsaPssParameters> other_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(64)
          .SetVariant(RsaSsaPssParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(RsaSsaPssParametersTest, HashTypeNotEqual) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<RsaSsaPssParameters> other_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(RsaSsaPssParametersTest, SaltLengthNotEqual) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<RsaSsaPssParameters> other_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(62)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(RsaSsaPssParametersTest, ModulusSizeNotEqual) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<RsaSsaPssParameters> other_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(RsaSsaPssParametersTest, PublicExponentNotEqual) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(64)
          .SetPublicExponent(kF4)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger nonF4_public_exponent =
      BigInteger(PublicExponentToString(1234567));
  util::StatusOr<RsaSsaPssParameters> other_parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(nonF4_public_exponent)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(64)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
