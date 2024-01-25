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

#include "tink/signature/ecdsa_parameters.h"

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
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  EcdsaParameters::CurveType curve_type;
  EcdsaParameters::HashType hash_type;
  EcdsaParameters::SignatureEncoding signature_encoding;
  EcdsaParameters::Variant variant;
  bool has_id_requirement;
};

using EcdsaParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    EcdsaParametersTestSuite, EcdsaParametersTest,
    Values(TestCase{EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::HashType::kSha256,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kTink,
                    /*has_id_requirement=*/true},
           TestCase{EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha384,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kCrunchy,
                    /*has_id_requirement=*/true},
           TestCase{EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha512,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    EcdsaParameters::Variant::kLegacy,
                    /*has_id_requirement=*/true},
           TestCase{EcdsaParameters::CurveType::kNistP521,
                    EcdsaParameters::HashType::kSha512,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    EcdsaParameters::Variant::kNoPrefix,
                    /*has_id_requirement=*/false}));

TEST_P(EcdsaParametersTest, BuildWorks) {
  TestCase test_case = GetParam();

  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetCurveType(), Eq(test_case.curve_type));
  EXPECT_THAT(parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(parameters->GetSignatureEncoding(),
              Eq(test_case.signature_encoding));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(EcdsaParametersTest, BuildWithInvalidVariantFails) {
  EXPECT_THAT(
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("unknown Variant")));
}

TEST(EcdsaParametersTest, BuildWithoutVariantFails) {
  EXPECT_THAT(
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Variant is not set")));
}

TEST(EcdsaParametersTest, BuildWithInvalidCurveTypeFails) {
  EXPECT_THAT(
      EcdsaParameters::Builder()
          .SetCurveType(
              EcdsaParameters::CurveType::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("unknown CurveType")));
}

TEST(EcdsaParametersTest, BuildWithoutCurveTypeFails) {
  EXPECT_THAT(
      EcdsaParameters::Builder()
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("CurveType is not set")));
}

TEST(EcdsaParametersTest, BuildWithInvalidHashTypeFails) {
  EXPECT_THAT(
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(
              EcdsaParameters::HashType::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("unknown HashType")));
}

TEST(EcdsaParametersTest, BuildWithoutHashTypeFails) {
  EXPECT_THAT(
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("HashType is not set")));
}

TEST(EcdsaParametersTest, BuildWithInvalidSignatureEncodingFails) {
  EXPECT_THAT(EcdsaParameters::Builder()
                  .SetCurveType(EcdsaParameters::CurveType::kNistP256)
                  .SetHashType(EcdsaParameters::HashType::kSha256)
                  .SetSignatureEncoding(
                      EcdsaParameters::SignatureEncoding::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .SetVariant(EcdsaParameters::Variant::kTink)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown SignatureEncoding")));
}

TEST(EcdsaParametersTest, BuildWithoutSignatureEncodingFails) {
  EXPECT_THAT(EcdsaParameters::Builder()
                  .SetCurveType(EcdsaParameters::CurveType::kNistP256)
                  .SetHashType(EcdsaParameters::HashType::kSha256)
                  .SetVariant(EcdsaParameters::Variant::kTink)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("SignatureEncoding is not set")));
}

TEST(EcdsaParametersTest, BuildWithIncompatibleHashTypeForCurveP256Fails) {
  // NIST_P256 curve requires SHA256
  EXPECT_THAT(
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha512)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("NIST_P256 curve requires SHA256")));
}

TEST(EcdsaParametersTest, BuildWithIncompatibleHashTypeForCurveP384Fails) {
  // NIST_P384 curve requires SHA384 or SHA512
  EXPECT_THAT(
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("NIST_P384 curve requires SHA384 or SHA512")));
}

TEST(EcdsaParametersTest, BuildWithIncompatibleHashTypeForCurveP521Fails) {
  // NIST_P521 curve requires SHA512
  EXPECT_THAT(
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP521)
          .SetHashType(EcdsaParameters::HashType::kSha384)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("NIST_P521 curve requires SHA512")));
}

TEST(EcdsaParametersTest, CopyConstructor) {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EcdsaParameters copy(*parameters);

  EXPECT_THAT(copy.GetCurveType(), Eq(EcdsaParameters::CurveType::kNistP256));
  EXPECT_THAT(copy.GetHashType(), Eq(EcdsaParameters::HashType::kSha256));
  EXPECT_THAT(copy.GetSignatureEncoding(),
              Eq(EcdsaParameters::SignatureEncoding::kDer));
  EXPECT_THAT(copy.GetVariant(), Eq(EcdsaParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(EcdsaParametersTest, CopyAssignment) {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EcdsaParameters copy = *parameters;

  EXPECT_THAT(copy.GetCurveType(), Eq(EcdsaParameters::CurveType::kNistP256));
  EXPECT_THAT(copy.GetHashType(), Eq(EcdsaParameters::HashType::kSha256));
  EXPECT_THAT(copy.GetSignatureEncoding(),
              Eq(EcdsaParameters::SignatureEncoding::kDer));
  EXPECT_THAT(copy.GetVariant(), Eq(EcdsaParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST_P(EcdsaParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EcdsaParameters> other_parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(EcdsaParametersTest, DifferentVariantNotEqual) {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EcdsaParameters> other_parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(EcdsaParametersTest, DifferentCurveTypeNotEqual) {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha512)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EcdsaParameters> other_parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP521)
          .SetHashType(EcdsaParameters::HashType::kSha512)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(EcdsaParametersTest, DifferentHashTypeNotEqual) {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha384)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EcdsaParameters> other_parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha512)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(EcdsaParametersTest, DifferentSignatureEncodingNotEqual) {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EcdsaParameters> other_parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
