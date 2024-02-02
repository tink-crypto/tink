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

#include "tink/signature/ecdsa_private_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#endif
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
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
  subtle::EllipticCurveType curve;
  EcdsaParameters::CurveType curve_type;
  EcdsaParameters::HashType hash_type;
  EcdsaParameters::SignatureEncoding signature_encoding;
  EcdsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using EcdsaPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    EcdsaPrivateKeyTestSuite, EcdsaPrivateKeyTest,
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

TEST_P(EcdsaPrivateKeyTest, CreatePrivateKeyWorks) {
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

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateKeyValue(GetPartialKeyAccess()),
              Eq(private_key_value));
}

TEST_P(EcdsaPrivateKeyTest, CreateMismatchedKeyPairFails) {
  TestCase test_case = GetParam();

  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key1 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key1, IsOk());

  EcPoint public_point(BigInteger(ec_key1->pub_x), BigInteger(ec_key1->pub_y));

  util::StatusOr<EcdsaPublicKey> public_key1 =
      EcdsaPublicKey::Create(*parameters, public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<internal::EcKey> ec_key2 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key2, IsOk());

  RestrictedBigInteger private_key_bytes2 =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key2->priv),
                           InsecureSecretKeyAccess::Get());

  EXPECT_THAT(EcdsaPrivateKey::Create(*public_key1, private_key_bytes2,
                                      GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid EC key pair")));
}

TEST_P(EcdsaPrivateKeyTest, PrivateKeyEquals) {
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

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<EcdsaPrivateKey> other_private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(EcdsaPrivateKeyTest, DifferentPublicKeyNotEqual) {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<EcdsaPublicKey> public_key1 =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<EcdsaPublicKey> public_key2 =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key1, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<EcdsaPrivateKey> other_private_key = EcdsaPrivateKey::Create(
      *public_key2, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(EcdsaPrivateKeyTest, DifferentKeyTypesNotEqual) {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
