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

#include "tink/hybrid/ecies_public_key.h"

#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/internal/ec_util.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::SizeIs;
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

using EciesPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    EciesPublicKeyTestSuite, EciesPublicKeyTest,
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

TEST_P(EciesPublicKeyTest, CreateNistCurvePublicKey) {
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

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetNistCurvePoint(GetPartialKeyAccess()),
              Eq(public_point));
  EXPECT_THAT(public_key->GetX25519CurvePointBytes(GetPartialKeyAccess()),
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

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(public_key->GetOutputPrefix(), IsEmpty());
  EXPECT_THAT(public_key->GetNistCurvePoint(GetPartialKeyAccess()),
              Eq(absl::nullopt));
  EXPECT_THAT(public_key->GetX25519CurvePointBytes(GetPartialKeyAccess()),
              Eq(public_key_bytes));
}

TEST(EciesPublicKeyTest, CreateX25519PublicKeyWithInvalidLength) {
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
      EciesPublicKey::CreateForCurveX25519(
          *params, public_key_bytes.substr(0, public_key_bytes.size() - 1),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesPublicKeyTest, CreateNistCurvePublicKeyWithInvalidPoint) {
  // Copied from "public point not on curve" Wycheproof test case in
  //
  // https://github.com/google/wycheproof/blob/master/testvectors/ecdh_secp256k1_test.json.
  std::string invalid_point = absl::HexStringToBytes(
      "3056301006072a8648ce3d020106052b8104000a0342000449c248edc659e18482b71057"
      "48a4b95d3a46952a5ba72da0d702dc97a64e99799d8cff7a5c4b925e4360ece25ccf307d"
      "7a9a7063286bbd16ef64c65f546757e4");

  util::StatusOr<int32_t> point_size =
      internal::EcPointEncodingSizeInBytes(subtle::EllipticCurveType::NIST_P256,
                                           subtle::EcPointFormat::UNCOMPRESSED);
  ASSERT_THAT(point_size, IsOk());
  ASSERT_THAT(*point_size, testing::Lt(invalid_point.size()));

  std::string public_key_bytes =
      invalid_point.substr(invalid_point.size() - *point_size, *point_size);
  // Uncompressed point format starts with a 0x04-byte.
  ASSERT_THAT(public_key_bytes, SizeIs(65));
  ASSERT_THAT(public_key_bytes[0], Eq(0x04));

  BigInteger x(public_key_bytes.substr(1, 32));
  BigInteger y(public_key_bytes.substr(33, 32));
  EcPoint point(x, y);

  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, point,
                                         /*id_requirement=*/absl::nullopt,
                                         GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(), StatusIs(absl::StatusCode::kInternal));
}

TEST(EciesPublicKeyTest,
     CreateX2559CurvePublicKeyWithInvalidIdRequirementFails) {
  util::StatusOr<EciesParameters> no_prefix_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_params, IsOk());

  util::StatusOr<EciesParameters> tink_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  EXPECT_THAT(EciesPublicKey::CreateForCurveX25519(
                  *no_prefix_params, public_key_bytes,
                  /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(EciesPublicKey::CreateForCurveX25519(
                  *tink_params, public_key_bytes,
                  /*id_requirement=*/absl::nullopt, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesPublicKeyTest,
     CreateNistCurvePublicKeyWithInvalidIdRequirementFails) {
  util::StatusOr<EciesParameters> no_prefix_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_params, IsOk());

  util::StatusOr<EciesParameters> tink_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  EXPECT_THAT(EciesPublicKey::CreateForNistCurve(
                  *no_prefix_params, public_point,
                  /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(EciesPublicKey::CreateForNistCurve(
                  *tink_params, public_point,
                  /*id_requirement=*/absl::nullopt, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EciesPublicKeyTest, NistCurvePublicKeyEquals) {
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

  util::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(EciesPublicKeyTest, X25519PublicKeyEquals) {
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

  util::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(EciesPublicKeyTest, DifferentParametersNotEqual) {
  util::StatusOr<EciesParameters> crunchy_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(crunchy_params, IsOk());

  util::StatusOr<EciesParameters> tink_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*crunchy_params, public_key_bytes,
                                           /*id_requirement=*/0x01020304,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForCurveX25519(*tink_params, public_key_bytes,
                                           /*id_requirement=*/0x01020304,
                                           GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(EciesPublicKeyTest, DifferentPublicPointsNotEqual) {
  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
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

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point1,
                                         /*id_requirement=*/123,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point2,
                                         /*id_requirement=*/123,
                                         GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(EciesPublicKeyTest, DifferentPublicKeyBytesNotEqual) {
  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes1 = subtle::Random::GetRandomBytes(32);
  std::string public_key_bytes2 = subtle::Random::GetRandomBytes(32);

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes1,
                                           /*id_requirement=*/0x01020304,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes2,
                                           /*id_requirement=*/0x01020304,
                                           GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(EciesPublicKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/0x01020304,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/0x02030405,
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
