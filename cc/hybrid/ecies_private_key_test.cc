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

#include "tink/hybrid/ecies_private_key.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#endif
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  subtle::EllipticCurveType curve;
  EciesParameters::CurveType curve_type;
  EciesParameters::HashType hash_type;
  subtle::EcPointFormat ec_point_format;
  EciesParameters::PointFormat point_format;
  EciesParameters::DemId dem_id;
  EciesParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using EciesPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    EciesPrivateKeyTestSuite, EciesPrivateKeyTest,
    Values(TestCase{subtle::EllipticCurveType::NIST_P256,
                    EciesParameters::CurveType::kNistP256,
                    EciesParameters::HashType::kSha256,
                    subtle::EcPointFormat::COMPRESSED,
                    EciesParameters::PointFormat::kCompressed,
                    EciesParameters::DemId::kAes128GcmRaw,
                    EciesParameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P384,
                    EciesParameters::CurveType::kNistP384,
                    EciesParameters::HashType::kSha384,
                    subtle::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
                    EciesParameters::PointFormat::kLegacyUncompressed,
                    EciesParameters::DemId::kAes256GcmRaw,
                    EciesParameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P521,
                    EciesParameters::CurveType::kNistP521,
                    EciesParameters::HashType::kSha512,
                    subtle::EcPointFormat::UNCOMPRESSED,
                    EciesParameters::PointFormat::kUncompressed,
                    EciesParameters::DemId::kAes256SivRaw,
                    EciesParameters::Variant::kNoPrefix,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(EciesPrivateKeyTest, CreateNistCurvePrivateKey) {
  TestCase test_case = GetParam();

  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetNistPrivateKeyValue(GetPartialKeyAccess()),
              Eq(private_key_value));
  EXPECT_THAT(private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(absl::nullopt));
}

TEST(EciesPublicKeyTest, CreateX25519PublicKey) {
  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      std::string(reinterpret_cast<const char*>((*x25519_key)->private_key),
                  internal::X25519KeyPrivKeySize()),
      InsecureSecretKeyAccess::Get());

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), IsEmpty());
  EXPECT_THAT(private_key->GetNistPrivateKeyValue(GetPartialKeyAccess()),
              Eq(absl::nullopt));
  EXPECT_THAT(private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
}

TEST_P(EciesPrivateKeyTest, CreateMismatchedNistCurveKeyPairFails) {
  TestCase test_case = GetParam();

  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key1 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key1, IsOk());

  EcPoint public_point(BigInteger(ec_key1->pub_x), BigInteger(ec_key1->pub_y));

  util::StatusOr<EciesPublicKey> public_key1 =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<internal::EcKey> ec_key2 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key2, IsOk());

  RestrictedBigInteger private_key_bytes2 =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key2->priv),
                           InsecureSecretKeyAccess::Get());

  EXPECT_THAT(EciesPrivateKey::CreateForNistCurve(
                  *public_key1, private_key_bytes2, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesPrivateKeyTest, CreateMismatchedX25519KeyPairFails) {
  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);
  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes = RestrictedData(
      subtle::Random::GetRandomBytes(32), InsecureSecretKeyAccess::Get());

  EXPECT_THAT(EciesPrivateKey::CreateForCurveX25519(
                  *public_key, private_key_bytes, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesPrivateKeyTest, CreateX25519PrivateKeyWithInvalidKeyLengthFails) {
  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  std::string private_key_input =
      std::string(reinterpret_cast<const char*>((*x25519_key)->private_key),
                  internal::X25519KeyPrivKeySize());
  RestrictedData expanded_private_key_bytes = RestrictedData(
      absl::StrCat(absl::HexStringToBytes("00"), private_key_input),
      InsecureSecretKeyAccess::Get());

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(
      EciesPrivateKey::CreateForCurveX25519(
          *public_key, expanded_private_key_bytes, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EciesPrivateKeyTest, NistCurvePrivateKeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<EciesPrivateKey> other_private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(EciesPrivateKeyTest, X25519PrivateKeyEquals) {
  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      std::string(reinterpret_cast<const char*>((*x25519_key)->private_key),
                  internal::X25519KeyPrivKeySize()),
      InsecureSecretKeyAccess::Get());

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<EciesPrivateKey> other_private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(EciesPrivateKeyTest, DifferentPublicKeyNotEqual) {
  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      std::string(reinterpret_cast<const char*>((*x25519_key)->private_key),
                  internal::X25519KeyPrivKeySize()),
      InsecureSecretKeyAccess::Get());

  util::StatusOr<EciesPublicKey> public_key123 =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/123,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key123, IsOk());

  util::StatusOr<EciesPublicKey> public_key456 =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/456,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key456, IsOk());

  util::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key123, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<EciesPrivateKey> other_private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key456, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(EciesPrivateKeyTest, DifferentKeyTypesNotEqual) {
  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      std::string(reinterpret_cast<const char*>((*x25519_key)->private_key),
                  internal::X25519KeyPrivKeySize()),
      InsecureSecretKeyAccess::Get());

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/123,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
