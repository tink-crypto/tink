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

#include "tink/signature/ecdsa_public_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/subtle/common_enums.h"
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

// Test case for P-256 downloaded from NIST
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing
const EcPoint& kP256EcPoint = *new EcPoint(
    BigInteger(absl::HexStringToBytes(
        "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287")),
    BigInteger(absl::HexStringToBytes(
        "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac")));

struct TestCase {
  subtle::EllipticCurveType curve;
  EcdsaParameters::CurveType curve_type;
  EcdsaParameters::HashType hash_type;
  EcdsaParameters::SignatureEncoding signature_encoding;
  EcdsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using EcdsaPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    EcdsaPublicKeyTestSuite, EcdsaPublicKeyTest,
    Values(TestCase{subtle::EllipticCurveType::NIST_P256,
                    EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::HashType::kSha256,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P384,
                    EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha384,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P384,
                    EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha384,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    EcdsaParameters::Variant::kLegacy,
                    /*id_requirement=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P521,
                    EcdsaParameters::CurveType::kNistP521,
                    EcdsaParameters::HashType::kSha512,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    EcdsaParameters::Variant::kNoPrefix,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(EcdsaPublicKeyTest, CreatePublicKeyWorks) {
  TestCase test_case = GetParam();

  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetPublicPoint(GetPartialKeyAccess()),
              Eq(public_point));
}

TEST(EcdsaPublicKeyTest, CreatePublicKeyWithInvalidIdRequirementFails) {
  util::StatusOr<EcdsaParameters> no_prefix_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_params, IsOk());

  util::StatusOr<EcdsaParameters> tink_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  EXPECT_THAT(
      EcdsaPublicKey::Create(*no_prefix_params, kP256EcPoint,
                             /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("key with ID requirement with parameters without ID "
                         "requirement")));

  EXPECT_THAT(EcdsaPublicKey::Create(*tink_params, kP256EcPoint,
                                     /*id_requirement=*/absl::nullopt,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key without ID requirement with parameters "
                                 "with ID requirement")));
}

TEST(EcdsaPublicKeyTest, CreatePublicKeyWithInvalidPointFails) {
  // Creates an invalid EC point, by modifying the Y coordinate of kP256EcPoint.
  EcPoint invalid_point(
      BigInteger(absl::HexStringToBytes(
          "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287")),
      BigInteger(absl::HexStringToBytes(
          "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ad")));

  util::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, invalid_point,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(), StatusIs(absl::StatusCode::kInternal));
}

TEST_P(EcdsaPublicKeyTest, PublicKeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EcdsaPublicKey> other_public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(EcdsaPublicKeyTest, DifferentParametersNotEqual) {
  util::StatusOr<EcdsaParameters> crunchy_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(crunchy_params, IsOk());

  util::StatusOr<EcdsaParameters> tink_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  util::StatusOr<EcdsaPublicKey> crunchy_public_key = EcdsaPublicKey::Create(
      *crunchy_params, kP256EcPoint,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(crunchy_public_key, IsOk());

  util::StatusOr<EcdsaPublicKey> tink_public_key = EcdsaPublicKey::Create(
      *tink_params, kP256EcPoint,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(tink_public_key, IsOk());

  EXPECT_TRUE(*tink_public_key != *crunchy_public_key);
  EXPECT_TRUE(*crunchy_public_key != *tink_public_key);
  EXPECT_FALSE(*tink_public_key == *crunchy_public_key);
  EXPECT_FALSE(*crunchy_public_key == *tink_public_key);
}

TEST(EcdsaPublicKeyTest, DifferentPublicPointsNotEqual) {
  util::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key1 =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key1, IsOk());
  util::StatusOr<internal::EcKey> ec_key2 =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key2, IsOk());

  EcPoint public_point1(BigInteger(ec_key1->pub_x), BigInteger(ec_key1->pub_y));
  EcPoint public_point2(BigInteger(ec_key2->pub_x), BigInteger(ec_key2->pub_y));

  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, public_point1,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EcdsaPublicKey> other_public_key = EcdsaPublicKey::Create(
      *params, public_point2,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(EcdsaPublicKeyTest, DifferentIdRequirementsNotEqual) {
  util::StatusOr<EcdsaParameters> tink_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *tink_params, kP256EcPoint,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EcdsaPublicKey> other_public_key = EcdsaPublicKey::Create(
      *tink_params, kP256EcPoint,
      /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
